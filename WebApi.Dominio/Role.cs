using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace WebApi.Dominio
{
    public class Role :IdentityRole<int>
    {
        public List<UserRole> UserRoles { get; set; }
    }
}
