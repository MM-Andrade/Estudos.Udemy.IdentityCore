using Microsoft.AspNetCore.Identity;

namespace WepApp.Identity
{
    public class MyUser : IdentityUser
    {
        public string NomeCompleto { get; set; }
        public string OrgId { get; set; }
        public string Member { get; set; } = "Member";
    }

    public class Organization
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }
}
