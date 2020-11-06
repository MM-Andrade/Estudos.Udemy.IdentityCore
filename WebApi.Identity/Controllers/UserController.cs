using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApi.Dominio;
using WebApi.Identity.Dto;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebApi.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize(AuthenticationSchemes = "Bearer")]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IMapper _mapper;

        public UserController(IConfiguration config, UserManager<User> userManager,
                                SignInManager<User> signInManager, IMapper mapper)
        {
            _config = config;
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
        }

        // GET api/<UserController>/5
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new UserDto());
        }

   
        [HttpGet("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(UserLoginDto userLoginDto)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(userLoginDto.UserName);
                var result = await _signInManager.CheckPasswordSignInAsync(user, userLoginDto.Password, false);

                if (result.Succeeded)
                {
                    var appUser = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedUserName == user.UserName.ToUpper());

                    var userToReturn = _mapper.Map<UserDto>(appUser);

                    return Ok(new { token = GenerateJWToken(appUser).Result, user = userToReturn });
                }
                return Unauthorized();

            }
            catch (System.Exception ex)
            {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR: {ex.Message}");
            }
        }

        // POST api/<UserController>
        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(UserDto userDto)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(userDto.UserName);
                if (user == null)
                {
                    user = new User()
                    {
                        UserName = userDto.UserName,
                        //fins didáticos:
                        Email = userDto.UserName,
                        NomeCompleto = userDto.NomeCompleto
                    };

                    var result = await _userManager.CreateAsync(user, userDto.Password);

                    if (result.Succeeded)
                    {
                        var appUser = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedUserName == user.UserName.ToUpper());

                        var token = GenerateJWToken(appUser).Result;

                        //var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home", new { Token = token, user.Email }, Request.Scheme);

                        //System.IO.File.WriteAllText("confirmEmaillink.txt", confirmationEmail);

                        return Ok(token);
                    }
                }
                return Unauthorized();
            }
            catch (System.Exception ex)
            {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR: {ex.Message}");
            }
        }

        /// <summary>
        /// Método responsável por geração do JWToken
        /// </summary>
        /// <param name="user"></param>
        /// <returns>Token criado </returns>
        private async Task<string> GenerateJWToken(User user)
        {

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            };

            //recuperação das roles que o usuário possui.
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            //cria uma chave de criptografia com a chave do AppSettings
            var key = new SymmetricSecurityKey(Encoding.ASCII
                        .GetBytes(_config.GetSection("AppSettings:Token").Value));

            //Criação de credencial com o tipo de criptografia a ser usada
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //geração da descrição do token
            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            //geração do token
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescription);

            //retorno do token criado
            return tokenHandler.WriteToken(token);
        }

        // PUT api/<UserController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<UserController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
