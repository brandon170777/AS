using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public required string UserId { get; set; }

        [Required]
        public required string PasswordHash { get; set; }

        public DateTime ChangedOn { get; set; } = DateTime.Now;
    }
}
