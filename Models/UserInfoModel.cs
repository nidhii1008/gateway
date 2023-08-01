using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace ITGateway.Models
{
 


  public class UserInfoModel
{
    [Key]
    public int id { get; set; }

    [StringLength(100)]
    public string username { get; set; }

    [StringLength(255)]
    public string password { get; set; }

    public int employee_id { get; set; }

    [ForeignKey("employee_id")]
    public virtual EmployeeModel Employee { get; set; }
}

}