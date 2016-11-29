using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security;

namespace Owin.Security.Saml
{
    /// <summary>
    /// A per-request authentication handler for the SamlAuthenticationMiddleware.
    /// </summary>
    public class SamlAuthenticationHandler : AuthenticationHandler<SamlAuthenticationOptions>
    {
        private const string HandledResponse = "HandledResponse";

        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new SamlAuthenticationHandler
        /// </summary>
        /// <param name="logger"></param>
        public SamlAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Handles Signout
        /// </summary>
        /// <returns></returns>
        protected override async Task ApplyResponseGrantAsync()
        {
            AuthenticationResponseRevoke signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (signout == null)
            {
                return;
            }

            var samlMessage = await GetSamlMessageFromRequestAsync();

            // WS Fed was "TokenAddress". Not sure this is the right endpoint
            samlMessage.IssuerAddress = Options.Configuration.ServiceProvider.Endpoints.DefaultLogoutEndpoint.RedirectUrl ?? string.Empty;
            samlMessage.Reply = string.Empty;

            // Set Wreply in order:
            // 1. properties.Redirect
            // 2. Options.SignOutWreply
            // 3. Options.Wreply
            var properties = signout.Properties;
            if (!string.IsNullOrEmpty(properties?.RedirectUri))
            {
                samlMessage.Reply = properties.RedirectUri;
            }
            else if (!string.IsNullOrWhiteSpace(Options.Configuration.ServiceProvider.Endpoints.DefaultLogoutEndpoint.RedirectUrl))
            {
                samlMessage.Reply = Options.Configuration.ServiceProvider.Endpoints.DefaultLogoutEndpoint.RedirectUrl;
            }

            var notification = new RedirectToIdentityProviderNotification<SamlMessage, SamlAuthenticationOptions>(Context, Options)
            {
                ProtocolMessage = samlMessage
            };
            await Options.Notifications.RedirectToIdentityProvider(notification);

            if (!notification.HandledResponse)
            {
                string redirectUri = notification.ProtocolMessage.BuildRedirectUrl();
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    _logger.WriteWarning("The sign-out redirect URI is malformed: " + redirectUri);
                }
                Response.Redirect(redirectUri);
            }
        }

        /// <summary>
        /// Handles Challenge
        /// </summary>
        /// <returns></returns>
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)
            {
                return;
            }

            var baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
            var currentUri = baseUri + Request.Path + Request.QueryString;

            // Save the original challenge URI so we can redirect back to it when we're done.
            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
                if (_logger.IsEnabled(TraceEventType.Verbose))
                {
                    _logger.WriteVerbose($"Setting the RedirectUri to {properties.RedirectUri}.");
                }
            }

            var samlMessage = await GetSamlMessageFromRequestAsync();
            if (samlMessage?.Assertion?.XmlAssertion != null && !string.IsNullOrWhiteSpace(Options.Configuration.AssertionLogPath))
            {
                var path = Path.Combine(Options.Configuration.AssertionLogPath, $"{Guid.NewGuid():N}.xml");
                File.WriteAllText(path, samlMessage.Assertion.XmlAssertion.OuterXml);
            }

            var notification = new RedirectToIdentityProviderNotification<SamlMessage, SamlAuthenticationOptions>(Context, Options)
            {
                ProtocolMessage = samlMessage
            };
            await Options.Notifications.RedirectToIdentityProvider(notification);

            if (!notification.HandledResponse)
            {
                string redirectUri = notification.ProtocolMessage.BuildRedirectUrl();
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    _logger.WriteWarning("The sign-in redirect URI is malformed: " + redirectUri);
                }
                Response.Redirect(redirectUri);
            }
        }

        /// <summary>
        /// Invoked to detect and process incoming authentication requests.
        /// </summary>
        /// <returns></returns>
        public override Task<bool> InvokeAsync()
        {
            return InvokeReplyPathAsync();
        }

        // Returns true if the request was handled, false if the next middleware should be invoked.
        private async Task<bool> InvokeReplyPathAsync()
        {
            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                return false;
            }

            string value;
            if (ticket.Properties.Dictionary.TryGetValue(HandledResponse, out value) && bool.Parse(value))
            {
                return true;
            }

            if (ticket.Identity != null)
            {
                Request.Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
            }

            // Redirect back to the original secured resource, if any.
            if (!string.IsNullOrWhiteSpace(ticket.Properties.RedirectUri))
            {
                _logger.WriteVerbose($"Redirecting to '{ticket.Properties.RedirectUri}'");

                Response.Redirect(ticket.Properties.RedirectUri);
                return true;
            }

            _logger.WriteVerbose("No RedirectUri was present in the context.");
            return false;
        }

        /// <summary>
        /// Invoked to process incoming authentication messages.
        /// </summary>
        /// <returns></returns>
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (!Request.Uri.AbsolutePath.Equals(Options.LoginPath, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return new SamlLoginHandler(Options).Invoke(Request.Context);

        }

        private async Task<SamlMessage> GetSamlMessageFromRequestAsync()
        {
            if ("POST".Equals(Request.Method, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(Request.ContentType) // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small
                && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) // May have media/type; charset=utf-8, allow partial match
                && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    // Buffer in case this body was not meant for us.
                    _logger.WriteVerbose("Buffering request body");

                    var memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);

                    Request.Body = memoryStream;
                }

                var form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                // TODO: a delegate on SamlAuthenticationOptions would allow for users to hook their own custom message.
                return new SamlMessage(form, Context, Options.Configuration);
            }

            return new SamlMessage(null, Context, Options.Configuration);
        }

        private static AuthenticationTicket GetHandledResponseTicket()
        {
            return new AuthenticationTicket(null,
                new AuthenticationProperties(new Dictionary<string, string>
                {
                    {HandledResponse, "true"}
                }));
        }
    }
}