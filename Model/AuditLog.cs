using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string Action { get; set; }   // Login, Logout, FailedLogin

        public DateTime TimeStamp { get; set; } = DateTime.Now;

        public string IPAddress { get; set; }

        public string Device { get; set; }
    }
}
