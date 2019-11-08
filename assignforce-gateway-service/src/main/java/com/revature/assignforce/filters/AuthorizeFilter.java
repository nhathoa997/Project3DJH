

@Component
public class AuthorizationFilter extends ZuulFilter {

    public AuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HEADER_STRING);

        if(header == null || !header.startsWith(PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String token = req.getHeader(HEADER_STRING);

        if(token != null) {
            JwkProvider provider = new UrlJwkProvider(PUBLIC_KEY_LOCATION);
            Jwk jwk = provider.get(KID);
            //Verification ver = JWT.require(Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null)).withIssuer(ISSUER).withAudience(AUDIENCE);

            Verification ver = JWT.require(Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null));

            DecodedJWT parsed = ver.build().verify(token);
            //String[] roles = parsed.getClaim("https://revature.com/roles").asArray(String.class);
            String[] roles = parsed.getClaim("username").asArray(String.class);

            if(roles.length > 0) {
                return new UsernamePasswordAuthenticationToken(user, null, roles);
            }
            return null;
        }
        return null;
    }

}
