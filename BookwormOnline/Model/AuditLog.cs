using System;
using System.ComponentModel.DataAnnotations;

namespace BookwormOnline.Model
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserEmail { get; set; } // Stores email of user

        [Required]
        public string Action { get; set; } // "Login" or "Logout"

        [Required]
        public DateTime Timestamp { get; set; } // Time of event
    }
}
