using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using ITGateway.Models;

namespace IT_Gateway.Models
{
    public class AssignedDevicesModel
    {
              [Key]
        public int A_id { get; set; }

        [ForeignKey("Employee")]
        public int? employee_id { get; set; }

        [Required]
        public Guid inventory_id { get; set; }

        public DateTime? created_at_utc { get; set; }

        public DateTime? updated_at_utc { get; set; }

        // Navigation property for the associated employee (assuming you have an Employee entity)
        public virtual EmployeeModel Employee { get; set; }

        // Navigation property for the associated inventory (assuming you have an Inventory entity)
        public virtual inventoryModel Inventory { get; set; }
    }
}