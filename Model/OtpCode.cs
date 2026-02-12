using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class OtpCode
    {
        [Key]
        public int Id { get; set; }

        public string UserId { get; set; }
        public string Code { get; set; }
        public DateTime Expiry { get; set; }
        public bool Used { get; set; } = false;
    }
}
