using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using SAML2;
using SAML2.Bindings;
using SAML2.Config;
using SAML2.Logging;
using SAML2.Protocol;
using SAML2.Utils;

namespace Owin.Security.Saml
{
    internal class SamlLoginHandler
    {
        private const string AssertionKey = "saml2:assertion";

        private static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(typeof(SamlLoginHandler));

        private readonly Saml2Configuration _configuration;
        private readonly Func<string, object> _getFromCache;
        private readonly IDictionary<string, object> _session;
        private readonly Action<string, object, DateTime> _setInCache;
        private readonly SamlAuthenticationOptions _options;

        /// <summary>
        /// Key used to save temporary session id
        /// </summary>
        public const string IdpTempSessionKey = "TempIDPId";

        /// <summary>
        /// Key used to override <c>ForceAuthn</c> setting
        /// </summary>
        public const string IdpForceAuthn = "IDPForceAuthn";

        /// <summary>
        /// Key used to override IsPassive setting
        /// </summary>
        public const string IdpIsPassive = "IDPIsPassive";

        /// <summary>
        /// Constructor for LoginHandler
        /// </summary>
        public SamlLoginHandler(SamlAuthenticationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options;
            _configuration = options.Configuration;
            _getFromCache = options.GetFromCache;
            _setInCache = options.SetInCache;
            _session = options.Session;
        }

        /// <summary>
        /// Invokes the login procedure (2nd leg of SP-Initiated login). Analagous to Saml20SignonHandler from ASP.Net DLL
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task<AuthenticationTicket> Invoke(IOwinContext context)
        {
            Logger.Debug(TraceMessages.SignOnHandlerCalled);

            ExceptionDispatchInfo exceptionDispatchInfo;
            try
            {
                if (!await _options.Notifications.MessageReceived.NotifyAndVerify(new MessageReceivedNotification<SamlMessage, SamlAuthenticationOptions>(context, _options)
                {
                    ProtocolMessage = new SamlMessage(context, _configuration, null)
                }))
                {
                    return null;
                }

                var requestParams = await HandleResponse(context);
                var assertion = context.Get<Saml20Assertion>(AssertionKey);

                if (!await _options.Notifications.SecurityTokenReceived.NotifyAndVerify(new SecurityTokenReceivedNotification<SamlMessage, SamlAuthenticationOptions>(context, _options)
                {
                    ProtocolMessage = new SamlMessage(context, _configuration, assertion)
                }))
                {
                    return null;
                }

                var ticket = await GetAuthenticationTicket(context, requestParams);
                if (!await _options.Notifications.SecurityTokenValidated.NotifyAndVerify(new SecurityTokenValidatedNotification<SamlMessage, SamlAuthenticationOptions>(context, _options)
                {
                    AuthenticationTicket = ticket,
                    ProtocolMessage = new SamlMessage(context, _configuration, assertion)
                }))
                {
                    return null;
                }
                
                // Flow possible changes
                context.Authentication.AuthenticationResponseGrant = new AuthenticationResponseGrant(ticket.Identity, ticket.Properties);

                return ticket;
            }
            catch (Exception ex)
            {
                exceptionDispatchInfo = ExceptionDispatchInfo.Capture(ex);
            }

            if (exceptionDispatchInfo != null)
            {
                Logger.Error("Exception occurred while processing message: " + exceptionDispatchInfo.SourceException);

                if (!await _options.Notifications.AuthenticationFailed.NotifyAndVerify(new AuthenticationFailedNotification<SamlMessage, SamlAuthenticationOptions>(context, _options)
                {
                    ProtocolMessage = new SamlMessage(context, _configuration, context.Get<Saml20Assertion>(AssertionKey)),
                    Exception = exceptionDispatchInfo.SourceException
                }))
                {
                    return null;
                }

                exceptionDispatchInfo.Throw();
            }

            return null;
        }

        private async Task HandleNotification<TOptions>(Func<BaseNotification<TOptions>, Task> notifierFunc, BaseNotification<TOptions> notificationOptions)
        {
            await notifierFunc(notificationOptions);
        }

        private async Task HandleNotification<TNotificaton, TOptions>(Func<TNotificaton, Task> notifierFunc, TNotificaton notificationOptions)
            where TNotificaton : BaseNotification<TOptions>
        {
            await HandleNotification((Func<BaseNotification<TOptions>, Task>) notifierFunc, notificationOptions);
        }

        private Task<AuthenticationTicket> GetAuthenticationTicket(IOwinContext context, NameValueCollection requestParams)
        {
            var assertion = context.Get<Saml20Assertion>(AssertionKey);
            if (assertion == null)
                throw new InvalidOperationException("no assertion found with which to create a ticket");

            var authenticationProperties = new AuthenticationProperties
            {
                ExpiresUtc = assertion.NotOnOrAfter,
                // IssuedUtc = DateTimeOffset.UtcNow,
                IsPersistent = true,
                AllowRefresh = true,
                RedirectUri = _options.RedirectAfterLogin
            };

            var relayState = requestParams["RelayState"];
            if (relayState != null)
            {
                var challengeProperties = new AuthenticationProperties(Compression.DeflateDecompress(relayState).FromDelimitedString().ToDictionary(k => k.Key, v => v.Value));
                if (challengeProperties.RedirectUri != null) authenticationProperties.RedirectUri = challengeProperties.RedirectUri;
                foreach (var kvp in challengeProperties.Dictionary.Except(authenticationProperties.Dictionary))
                    authenticationProperties.Dictionary.Add(kvp);
            }
            return Task.FromResult(new AuthenticationTicket(assertion.ToClaimsIdentity(_options.SignInAsAuthenticationType), authenticationProperties));
        }

        private Task<NameValueCollection> HandleResponse(IOwinContext context)
        {
            Action<Saml20Assertion> loginAction = a => DoSignOn(context, a);

            // Some IdP's are known to fail to set an actual value in the SOAPAction header
            // so we just check for the existence of the header field.
            if (context.Request.Headers.ContainsKey(SoapConstants.SoapAction))
            {
                Utility.HandleSoap(
                    GetBuilder(context),
                    context.Request.Body,
                    _configuration,
                    loginAction,
                    _getFromCache,
                    _setInCache,
                    _session);
                return Task.FromResult(context.Request.GetRequestParameters().ToNameValueCollection());
            }

            var requestParams = context.Request.GetRequestParameters().ToNameValueCollection();
            if (!string.IsNullOrWhiteSpace(requestParams["SAMLart"]))
            {
                HandleArtifact(context);
            }

            var samlResponse = requestParams["SamlResponse"];
            if (!string.IsNullOrWhiteSpace(samlResponse))
            {
                var assertion = Utility.HandleResponse(_configuration, samlResponse, _session, _getFromCache, _setInCache);
                loginAction(assertion);
            }
            else
            {
                if (_configuration.CommonDomainCookie.Enabled && context.Request.Query["r"] == null
                    && requestParams["cidp"] == null)
                {
                    Logger.Debug(TraceMessages.CommonDomainCookieRedirectForDiscovery);
                    context.Response.Redirect(_configuration.CommonDomainCookie.LocalReaderEndpoint);
                }
                else
                {
                    Logger.WarnFormat(ErrorMessages.UnauthenticatedAccess, context.Request.Uri.OriginalString);
                    throw new InvalidOperationException("Response request recieved without any response data");
                }
            }
            return Task.FromResult(requestParams);
        }

        private void HandleArtifact(IOwinContext context)
        {
            var builder = GetBuilder(context);
            // TODO: Need params version of these!
            var inputStream = builder.ResolveArtifact(context.Request.Query["SAMLart"], context.Request.Query["relayState"], _configuration);

            Utility.HandleSoap(builder, inputStream, _configuration, a => DoSignOn(context, a), _getFromCache, _setInCache, _session);
        }

        private HttpArtifactBindingBuilder GetBuilder(IOwinContext context)
        {
            return new HttpArtifactBindingBuilder(
                _configuration,
                context.Response.Redirect,
                m => SendResponseMessage(m, context));
        }

        private static void SendResponseMessage(string message, IOwinContext context)
        {
            context.Response.ContentType = "text/xml";
            using (var writer = new StreamWriter(context.Response.Body))
            {
                writer.Write(HttpSoapBindingBuilder.WrapInSoapEnvelope(message));
            }
        }


        /// <summary>
        /// Handles executing the login.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="assertion">The assertion.</param>
        private void DoSignOn(IOwinContext context, Saml20Assertion assertion)
        {
            context.Set(AssertionKey, assertion);
            var subject = assertion.Subject ?? new SAML2.Schema.Core.NameId();
            Logger.DebugFormat(TraceMessages.SignOnProcessed, assertion.SessionIndex, subject.Value, subject.Format);
        }
    }
}
