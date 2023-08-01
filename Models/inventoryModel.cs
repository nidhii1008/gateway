using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IT_Gateway.Models
{
    public class inventoryModel
    {
  [Key]
        public Guid inventory_id { get; set; }

        [ForeignKey("Device")]
        public int device_id { get; set; }

        public DateTime? created_at_utc { get; set; }

        public DateTime? updated_at_utc { get; set; }

        public string device_state { get; set; }

        // Navigation property for the associated device (assuming you have a Device entity)
        public virtual DevicesModel Device { get; set; }
    }
}