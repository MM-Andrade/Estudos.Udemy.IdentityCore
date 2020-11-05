using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Threading.Tasks;
using WepApp.Identity.Models;
using ForgotPasswordModel = WepApp.Identity.Models.ForgotPasswordModel;
using LoginModel = WepApp.Identity.Models.LoginModel;
using RegisterModel = WepApp.Identity.Models.RegisterModel;
using ResetPasswordModel = WepApp.Identity.Models.ResetPasswordModel;

namespace WepApp.Identity.Controllers
{

    public class HomeController : Controller
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<MyUser> _userClaimsPrincipalFactory;
        private readonly SignInManager<MyUser> _signInManager;

        public HomeController(UserManager<MyUser> userManager,
            IUserClaimsPrincipalFactory<MyUser> userClaimsPrincipalFactory,
            SignInManager<MyUser> signInManager)
        {
            _userManager = userManager;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _signInManager = signInManager;
        }


        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public async Task<IActionResult> Register()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {

            //se usar [ApiController] ele ja faz na controller toda a validação (mas funciona apenas em API)
            if (ModelState.IsValid)
            {//validações através da viewlmodel/dataannontations ok ? 

                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null)
                {
                    user = new MyUser()
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        //fins didáticos:
                        Email = model.UserName
                    };

                    var result = await _userManager.CreateAsync(
                        user, model.Password);

                    if (result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home", new { Token = token, user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmEmaillink.txt", confirmationEmail);
                    }
                    else
                    {
                        foreach (var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }
                        return View();
                    }
                }

                return View("Success");
            }

            return View();
        }


        public async Task<IActionResult> Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            //se usar [ApiController] ele ja faz na controller toda a validação (mas funciona apenas em API)
            if (ModelState.IsValid)
            {//validações através da viewlmodel/dataannontations ok ? 

                var user = await _userManager.FindByNameAsync(model.UserName);
                //verifica se o user foi encontrado e não está bloqueado
                if (user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    //verifica o usuario encontrado se a senha corresponde a senha cadastrada
                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        if (!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            ModelState.AddModelError("", "Email inválido");
                            return View();
                        }
                        if (!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            ModelState.AddModelError("", "O e-mail não está confirmado!");
                            return View();
                        }

                        var principal = await _userClaimsPrincipalFactory.CreateAsync(user);

                        //2FA
                        if (await _userManager.GetTwoFactorEnabledAsync(user))
                        {
                            var validator = await _userManager.GetValidTwoFactorProvidersAsync(user);

                            if (validator.Contains("Email"))
                            {//sim, contem o email, então vou gerar o token
                                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                                System.IO.File.WriteAllText("email2fa.txt", token);
                            }

                            await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                Store2FA(user.Id, "Email"));

                            return RedirectToAction("TwoFactor");
                        }


                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);
                        return RedirectToAction("About");
                    }

                    #region Criação manual de cookies
                    //    //var identity = new ClaimsIdentity("cookies");
                    //    //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    //    //identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                    //    //await HttpContext.SignInAsync("cookies", new ClaimsPrincipal(identity));

                    //    //var identity = new ClaimsIdentity("Identity.Application");
                    //    //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    //    //identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                    //    //await HttpContext.SignInAsync("Identity.Application", new ClaimsPrincipal(identity));
                    #endregion
                    #region signinmanager
                    //implementação do SignIn
                    //enviado usuário e senha, não deixar o usuário logado após browser fechado e não ter lock do usuário caso tenha errado a senha
                    //vantagens: desenvolvimento rápido
                    //desvantagens: não ter visão do que acontece dentro do método (nome de cookie gerado, como é feita validação, claims etc)
                    //var signInResult = await _signInManager.PasswordSignInAsync(
                    //    model.UserName, model.Password, false, false);
                    //if (signInResult.Succeeded)
                    //{
                    //    return RedirectToAction("About");
                    //}
                    #endregion
                }

                //incrementa uma tentativa de acesso ao usuário
                await _userManager.AccessFailedAsync(user);

                //verifica se o user ta bloqueado
                if (await _userManager.IsLockedOutAsync(user))
                {//sim
                    //enviar email com sugestão de troca de senha
                }
            }
            ModelState.AddModelError("", "Usuário ou senha inválida!");
            return View();
        }

        private ClaimsPrincipal Store2FA(string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim> {
                new Claim("sub", userId),
                new Claim("arm",provider)
                }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

        public IActionResult Success()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            return View();
        }

        public async Task<IActionResult> ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                //usuário encontrado através do email ?
                if (user != null)
                {//sim
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetUrl = Url.Action("ResetPassword", "Home", new { token = token, email = model.Email }, Request.Scheme);

                    //ao invés de enviar email, para fins didáticos estou gerando um txt com o link de reset
                    System.IO.File.WriteAllText("resetlink.txt", resetUrl);

                    ViewBag.Mensagem = "Link de reset de senha gerado";
                    return View("Success");
                }
                else
                {//usuário não encontrado
                    ViewBag.Mensagem = "Usuário não encontrado";
                    return View();
                }
            }
            ModelState.AddModelError("", "Invalid Request!");
            return View();
        }


        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            return View(new Models.ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                //usuário encontrado através do email ?
                if (user != null)
                {//sim
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (!result.Succeeded)
                    {
                        foreach (var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }
                    }
                    return View();
                }
                return View();
            }
            ModelState.AddModelError("", "Invalid Request!");
            return View();
        }

        public async Task<IActionResult> ConfirmEmailAddress(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return View("Success");
                }
            }
            return View("Error");
        }


        public async Task<IActionResult> TwoFactor()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactorModel model)
        {

            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Seu token expirou!");
                return View();
            }
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));
                if (user != null)
                {
                    var isvalid = await _userManager.VerifyTwoFactorTokenAsync(user, result.Principal.FindFirstValue("arm"), model.Token);

                    if (isvalid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
                        var claimsPrincipal = await _userClaimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                        return RedirectToAction("About");
                    }

                    ModelState.AddModelError("", "Invalid Token");
                    return View();
                }
                ModelState.AddModelError("", "Invalid Request");
            }
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }


    }
}
