package idp

import (
	"crypto/sha256"
	"log"
	"log/slog"
	"module/utils"
	"net/http"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	"github.com/zitadel/logging"

	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	pathLoggedOut = "/logged-out"
)

func init() {
	/*client, err := models.CreateNativeClient(1, 5, 5, "native", []string{})
	if err != nil {
		log.Fatal(err)
	}
	err = client.SaveClient()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(client.GetID())
	*/
	// create a user
	/*user := models.NewUser("user", "first", "last", "asd", "user@")
	err := user.SaveUser()
	if err != nil {
		log.Fatal(err)
	}*/

}

// StorageOP is a combination of the op.Storage interface and the authenticate interface
type StorageOP interface {
	op.Storage
	authenticate
}

// simple counter for request IDs
var counter atomic.Int64

// SetupServer creates an OIDC server with Issuer=http://localhost:<port>
func SetupServer(issuer string, storage StorageOP, logger *slog.Logger, wrapServer bool, extraOptions ...op.Option) chi.Router {

	// generate a random key for the encryption of the tokens
	key := sha256.Sum256(utils.GenRandByteSlice(32))

	router := chi.NewRouter()
	router.Use(logging.Middleware(
		logging.WithLogger(logger),
		logging.WithIDFunc(func() slog.Attr {
			return slog.Int64("id", counter.Add(1))
		}),
	))

	// for simplicity, we provide a very small default page for users who have signed out
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("signed out successfully"))
		// no need to check/log error, this will be handled by the middleware.
	})

	// creation of the OpenIDProvider
	provider, err := newOP(storage, issuer, key, logger, extraOptions...)
	if err != nil {
		log.Fatal(err)
	}

	//the provider will only take care of the OpenID Protocol, so there must be some sort of UI for the login process
	//for the simplicity of the example this means a simple page with username and password field
	//be sure to provide an IssuerInterceptor with the IssuerFromRequest from the OP so the login can select / and pass it to the storage
	l := NewLogin(storage, op.AuthCallbackURL(provider), op.NewIssuerInterceptor(provider.IssuerFromRequest))

	// regardless of how many pages / steps there are in the process, the UI must be registered in the router,
	// so we will direct all calls to /login to the login UI
	router.Mount("/login/", http.StripPrefix("/login", l.router))

	handler := http.Handler(provider)
	if wrapServer {
		handler = op.RegisterLegacyServer(op.NewLegacyServer(provider, *op.DefaultEndpoints), op.AuthorizeCallbackHandler(provider))
	}

	// we register the http handler of the OP on the root, so that the discovery endpoint (/.well-known/openid-configuration)
	// is served on the correct path
	//
	// if your issuer ends with a path (e.g. http://localhost:9998/custom/path/),
	// then you would have to set the path prefix (/custom/path/)
	router.Mount("/", handler)

	return router
}

// newOP will create an OpenID Provider for localhost on a specified port with a given encryption key
// and a predefined default logout uri
// it will enable all options (see descriptions)
func newOP(storage op.Storage, issuer string, key [32]byte, logger *slog.Logger, extraOptions ...op.Option) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey: key,

		// will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		// enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		// enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: true,

		// enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: false,

		// enables refresh_token grant use
		GrantTypeRefreshToken: true,

		// enables use of the `request` Object parameter
		RequestObjectSupported: true,
	}
	cors := &cors.Options{AllowedMethods: []string{"GET", "POST"}, AllowedHeaders: []string{"Authorization", "Content-Type"}}
	handler, err := op.NewProvider(config, storage, op.StaticIssuer(issuer),
		append([]op.Option{
			op.WithAllowInsecure(),
			op.WithCORSOptions(cors),
		}, extraOptions...)...,
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}
