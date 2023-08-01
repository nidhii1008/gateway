using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
   using System;
   using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
namespace ITGateway.Models
{
    public class EmployeeModel
{
    [Key] // Primary Key Constraint
    public int employee_id { get; set; }

    [Required] // NOT NULL Constraint
    [StringLength(255)] // String Length Constraint
    public string employee_name { get; set; }

    public DateTime? created_at_utc { get; set; } // Nullable DateTime

    public DateTime? updated_at_utc { get; set; } // Nullable DateTime

    [StringLength(100)] // String Length Constraint
    public string created_by { get; set; }

    [StringLength(100)] // String Length Constraint
    public string updated_by { get; set; }

    [StringLength(255)] // String Length Constraint
    public string employee_mail { get; set; }

    // Additional constraints or properties can be added as needed
}

}