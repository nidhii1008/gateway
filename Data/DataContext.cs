using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using ITGateway.Models;
using IT_Gateway.Models;

namespace ITGateway.Data
{
   public class DataContext : DbContext
{
        private readonly DbContextOptions _options;

        public DataContext(DbContextOptions options) : base(options)
        {
        _options=options; 
        }
        public DbSet<EmployeeModel>employees{get;set;}
        public DbSet<UserInfoModel>UserInfo {get;set;}
        public DbSet<DevicesModel>Device {get;set;}
        public DbSet<inventoryModel> inventory{get;set;}
        public DbSet<AssignedDevicesModel>AssignedDevices{get;set;}
        //public DbSe
    // public DbSet<Employee> Employees { get; set; }

    // Add other DbSet properties for other model classes if necessary
}
}