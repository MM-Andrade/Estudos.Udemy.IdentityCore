using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace WebApi.Dominio
{
    public class User : IdentityUser<int>
    {
        public string NomeCompleto { get; set; }
        public string OrgId { get; set; }
        public string Member { get; set; } = "Member";


        public List<UserRole> UserRoles { get; set; }
    }
}
