#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "mod_perl.h"
#include "ap_provider.h"
#include "mod_auth.h"

static AV *providers = Nullav; /* @{$cfg->{basic}}, cached per-request   */

static int call_provider(request_rec *r, const char *type, 
                         const char *user, const char *cred, char **rethash)
{
  SV *provider = Nullsv;       /* the name of the Perl provider to call  */
  modperl_handler_t *handler;  /* the actual provider as a Perl handler  */
  AV *args = Nullav;           /* @_ to Perl handler                     */
  SV *hash = newSV(0);         /* scalar reference in @_ for Digest auth */
  SV *cfg;                     /* $cfg from directive handlers           */
  SV **svp;                    /* hash within $cfg, %{$cfg}              */
  int status;                  /* the status this function returns       */

  if (! apr_table_get(r->notes, "AUTHEN_HOOK_INIT_REQUEST")) {

    /* initialize a clean copy of the Perl provider array (eg, @{$cfg->{basic}})
     * (eg, @{$cfg->{basic}}) on each request.  because this function is
     * the sole function registered for all Perl providers, it is 
     * called multiple times per request - caching the provider array is 
     * the only way we can keep track of which Perl callbacks we've processed
     * for this request.
     * 
     * oh, and using r->notes instead of per-request cleanups helps us with
     * internal redirects, which is a nice bonus.  */

    MP_TRACE_d(MP_FUNC, 
               "Apache::AuthenHook - initializing request\n");

    /* first, get the config object ($cfg) populated by the Perl
     * directive handlers.  This returns the same object as 
     * Apache::Module->get_config().
     */
    cfg = modperl_module_config_get_obj(aTHX_ newSVpvn("Apache::AuthenHook", 18), 
                                        r->server, r->per_dir_config);
  
    if (! cfg) {
      MP_TRACE_d(MP_FUNC, 
                 "Apache::AuthenHook - config object not found\n");
  
      return AUTH_GENERAL_ERROR;
    }
  
    /* isolate $cfg->{basic} */
    svp = hv_fetch((HV *)SvRV(cfg), type, strlen(type), FALSE);

    if (SvROK(*svp) && (SvTYPE(SvRV(*svp)) == SVt_PVAV)) {
      /* if $cfg->{basic} holds a reference to an array, dereference
       * and initialize provider array for this request  */

      AV *av = (AV *)SvRV(*svp);   /* temporary storage */

      providers = av_make(av_len(av)+1, AvARRAY(av));

      MP_TRACE_d(MP_FUNC, 
                 "Apache::AuthenHook - found %d providers\n", 
                 av_len(av)+1);
    }
    else {
      MP_TRACE_d(MP_FUNC, 
                 "Apache::AuthenHook - provider array not found\n");

      return AUTH_GENERAL_ERROR;
    }

    /* set the note so we don't initialize again for this (sub)request */
    apr_table_setn(r->notes, "AUTHEN_HOOK_INIT_REQUEST", "1");
  
  }  /* end once per-request processing */
    
  /* shift off the next provider from the provider array */
  provider = av_shift(providers);

  if (! SvOK(provider)) {
    MP_TRACE_d(MP_FUNC,
               "Apache::AuthenHook - provider not found\n");

    return AUTH_GENERAL_ERROR;
  }

  /* populate @_ for the callback, starting with $r */
  modperl_handler_make_args(aTHX_ &args,
                           "Apache::RequestRec", r, NULL);

  /* now for the username and password(Basic) or realm(Digest) */
  av_push(args, newSVpv(user, 0));
  av_push(args, newSVpv(cred, 0));

  /* Digest authentication requires an extra argument - 
   * the scalar reference to be populated with the lookup hash */

  if (! strcmp(type, "digest")) {
    av_push(args, newRV_inc(hash));
  }

  /* at this point, we know which provider we're supposed to 
   * be calling and have populated the argument list.  now,
   * issue the callback using native mod_perl routines.  */

  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "Apache::AuthenHook - trying provider %s for %s", 
                SvPVX(provider), r->uri);

  handler = modperl_handler_new(r->pool, SvPV_nolen(provider));
  status  = modperl_callback(aTHX_ handler, r->pool, r, r->server, args);

  MP_TRACE_d(MP_FUNC, 
             "Apache::AuthenHook - provider returned %d\n", 
             status);

  /* unfortunately, modperl_callback forces the status into an HTTP_
   * status or OK, so I can't give Perl handlers meaningful access to
   * the AUTH_ constants without implementing my own callback routines.
   * this is the only real difference between the Perl and C API.
   *
   * while the switch statment in the C callback function takes care of 
   * the translation back to AUTH_ constants for us, there is still 
   * a little more work left  */

  if (status == OK && ! strcmp(type, "digest")) {

    /* for Digest we need to send the hash back for verification 
     * via mod_auth_digest */

    /* sanity checking - make sure that the scalar references a string */
    if (SvTYPE(hash) == SVt_PV) {
      *rethash = SvPV_nolen(hash);
    }
    else {
      MP_TRACE_d(MP_FUNC, 
                 "Apache::AuthenHook - returned hash not a string\n");

      status = AUTH_GENERAL_ERROR;
    }
  }
  else if (status == HTTP_INTERNAL_SERVER_ERROR) {

    /* write $@ to the error_log in the case of an error */
    modperl_errsv(aTHX_ status, r, NULL);
  }

  /* decrement args, as required by modperl_callback */
  SvREFCNT_dec((SV*)args);

  /* return whatever status the Perl provider returned */
  return status;
}

static authn_status check_password(request_rec *r, const char *user,
                                   const char *password)
{
  int status;

  MP_TRACE_d(MP_FUNC, 
             "Apache::AuthenHook - calling Basic handler\n");

  status = call_provider(r, "basic", user, password, NULL);

  /* determine which AUTH_ status we should return based on
   * what HTTP_ status the Perl provider returned.  and yes, 
   * this routine could be reused if I wanted to be less specific
   * with the log messages...  */
 
  switch(status) {
    case AUTH_GENERAL_ERROR:
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Apache::AuthenHook - yikes! something bad happened!");
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - try running with PerlTrace d");

      /* status is already AUTH_GENERAL_ERROR */
      break;
  
    case OK:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - user '%s', password '%s' verified",
                    user, password);

      status = AUTH_GRANTED;
      break;

    case DECLINED:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - passing user '%s' to next provider",
                    user);

      status = AUTH_USER_NOT_FOUND;
      break;
 
    default:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - user '%s', password '%s' denied",
                    user, password);

      status = AUTH_DENIED;
  };

  return status;
}

static authn_status get_realm_hash(request_rec *r, const char *user,
                                   const char *realm, char **rethash)
{
  int status;

  MP_TRACE_d(MP_FUNC, 
             "Apache::AuthenHook - calling Digest handler\n");

  status = call_provider(r, "digest", user, realm, &*rethash);

  switch(status) {
    case AUTH_GENERAL_ERROR:
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Apache::AuthenHook - yikes! something bad happened!");
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - try running with PerlTrace d");
      break;

    case OK:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - user '%s', hash '%s' found in realm '%s'",
                    user, *rethash, realm);

      status = AUTH_USER_FOUND;
      break;

    case DECLINED:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - passing user '%s' to next provider",
                    user);

      status = AUTH_USER_NOT_FOUND;
      break;
 
    default:
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Apache::AuthenHook - user '%s' in realm '%s' denied",
                    user, realm);

      status = AUTH_DENIED;
  };

  return status;
}

static const authn_provider authn_AAH_provider =
{
  &check_password,
  &get_realm_hash,
};

MODULE = Apache::AuthenHook    PACKAGE = Apache::AuthenHook

PROTOTYPES: DISABLE

void
register_provider(provider)
  SV *provider

  CODE:

    MP_TRACE_d(MP_FUNC, 
               "Apache::AuthenHook - registering provider %s\n", 
               SvPV_nolen(provider));

    ap_register_provider(modperl_global_get_pconf(), 
                         AUTHN_PROVIDER_GROUP, 
                         SvPV_nolen(newSVsv(provider)), "0",
                         &authn_AAH_provider);
