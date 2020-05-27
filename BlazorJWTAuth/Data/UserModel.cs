using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BlazorJWTAuth.Data
{
    public class UserModel
    {
        public string UserName { get; set; }
        public string Pass { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
    }
}
