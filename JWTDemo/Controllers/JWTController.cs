using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web.Http;

namespace JWTDemo.Controllers
{
    [RoutePrefix("api/jwt")]
    public class JWTController : ApiController
    {
        private string clientId = "test_id"; //CleintId
        private string audience = "https://api.alt.www4.irs.gov/"; //IRS Server
        private string private_key = "MyPassUsedtoEncryptTheToken@2023";


        [HttpGet, Route("client")]
        public IHttpActionResult GetClientJWT()
        {
            var clientJWT = GenerateClientJWT();
            return Ok(new { ClientJWT = clientJWT });
        }

        [HttpGet, Route("user")]
        public IHttpActionResult GetUserJWT()
        {
            
            var userJWT = GenerateUserJWT("dasmith", "345870");
            return Ok(new { UserJWT = userJWT });
        }

        public string GenerateClientJWT()
        {

            DateTime issued = DateTime.UtcNow;
            DateTime expired = issued.AddMinutes(15);

            int lat = (int)(issued - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            int exp = (int)(expired - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            var authClaims = new List<Claim>() {
                new Claim(JwtRegisteredClaimNames.Iss, clientId),
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Aud, audience),
                new Claim(JwtRegisteredClaimNames.Iat, lat.ToString(), ClaimValueTypes.Integer),
                new Claim(JwtRegisteredClaimNames.Exp, exp.ToString(), ClaimValueTypes.Integer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(private_key));
            authSigninKey.KeyId = "test_kid";

            var token = new JwtSecurityToken(
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
            );

            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt_token;
        }

        public string GenerateUserJWT(string userId, string customerId)
        {

            DateTime issued = DateTime.UtcNow;
            DateTime expired = issued.AddMinutes(15);

            int lat = (int)(issued - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            int exp = (int)(expired - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            var authClaims = new List<Claim>() {
                new Claim(JwtRegisteredClaimNames.Iss, clientId),
                new Claim(JwtRegisteredClaimNames.Sub, userId + "-" + customerId),
                new Claim(JwtRegisteredClaimNames.Aud, audience),
                new Claim(JwtRegisteredClaimNames.Iat, lat.ToString(), ClaimValueTypes.Integer),
                new Claim(JwtRegisteredClaimNames.Exp, exp.ToString(), ClaimValueTypes.Integer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(private_key));
            authSigninKey.KeyId = "test_kid";

            var token = new JwtSecurityToken(
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
            );

            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt_token;
        }
    }
}
