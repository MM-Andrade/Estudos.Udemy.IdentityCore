using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace WepApp.Identity.Helper
{
    public class NaoContemValidadorSenha<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var username = await manager.GetUserNameAsync(user);
            if(username == password)
            {
                return IdentityResult.Failed(
                    new IdentityError { Description = "a senha não pode ser igual ao usuário..." });
            }
            if (password.Contains("password"))
            {
                return IdentityResult.Failed(
                    new IdentityError { Description = "a senha não pode ser password..." });
            }

            return IdentityResult.Success;
        }
    }
}
