using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ITGateway.Models;
using ITGateway.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using IT_Gateway.Models;
// using System.Web.Mvc; 
namespace ITGateway.Controllers;
public class HomeController : Controller
{
    private readonly DataContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;
    public HomeController(DataContext context, IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
    }
    // public ActionResult BeforeLayoutContent()
    // {
    //     // Your logic here
    //     return PartialView("_BeforeLayoutContent");
    // }
 
    public IActionResult Index()
    {
        return View();
    }
    public IActionResult Privacy()
    {
        return View();
    }

      public IActionResult UserPage()
    {
        return View();
    }

    // public IActionResult Admin()
    // {
    //     return View();
    // }
    private string HashPassword(string password)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
[HttpGet("/Home/Admin")]
 public IActionResult Admin()
    {
        List<DevicesModel> devices = GetDevicesFromBackend();
        return View(devices);
    }
    private List<DevicesModel> GetDevicesFromBackend()
    {
        var devicesList= new List<DevicesModel>();
        try{
            devicesList=_context.Device.ToList();
        }catch(Exception ex){
            Console.WriteLine(ex.InnerException);
        }
        return devicesList;
    }
//    b
    [HttpGet("/Home/Index")]
    public ActionResult<string> UserLogin(string userName, string Password)
    {
        if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(Password))
        {
            // Render the login form
            return View("Index");
        }
        string hashedPassword = HashPassword(Password);
        var user = _context.UserInfo.SingleOrDefault(u => u.username == userName);
        if (user != null && hashedPassword == user.password)
        {
            var token = GenerateJwtToken(user.username);
            // HttpContext.Session.SetString("JwtToken", token);
            Response.Cookies.Append("JwtToken", token);
            _httpContextAccessor.HttpContext.Session.SetString("Username", user.username);
            string x= _httpContextAccessor.HttpContext.Session.GetString("Username");
            Console.WriteLine(x);
            //    string username = _httpContextAccessor.HttpContext.Session.GetString("Username"); retrieving
            // _httpContextAccessor.HttpContext.Session.SetInt32("Age", 30);
            // var emp = _context.employees.Find((_context.UserInfo.SingleOrDefault(u => u.username == userName).employee_id));
            //  if(emp.IsAdmin==1){
            //  return RedirectToAction("Admin");
            //  }
            //  else if(emp.IsAdmin==0){
            //     return RedirectToAction("User");
            //  }
        }
         return View("Index");
    }
[HttpPost("/Home/Admin")]
public IActionResult AddDevice(string deviceName)
{
    if (string.IsNullOrEmpty(deviceName))
    {
        return BadRequest("Device name is required.");
    }
    string userName = _httpContextAccessor.HttpContext.Session.GetString("Username");
    Console.WriteLine("username" + userName);
    var device = new DevicesModel
    {
        device_name = deviceName,
        created_by = userName,
        created_at_utc = DateTime.UtcNow,
        updated_at_utc = DateTime.UtcNow
    };
    _context.Device.Add(device);
    _context.SaveChanges();
    return Json(new { Message = "Device added successfully." });
}
    [HttpPost("/Home/Admin/AssignDevice")]
    public ActionResult<string> AssignDevice([FromBody] AssignDeviceData Data)
    {
        try{
            int deviceId=int.Parse(Data.device_id);
        int employeeId=int.Parse(Data.employee_id);
        List<inventoryModel> inventoryList = _context.inventory.ToList();
        var unassignedItems = inventoryList.Where(u => u.device_id == deviceId  && u.Specifications==Data.Specifications &&u.device_state == "Not Assigned").ToList();
        Console.WriteLine("Total unassigned items for deviceId " + deviceId + ": " + unassignedItems.Count+" "+employeeId);
        if (unassignedItems.Count > 0)
        {
            Random random = new Random();
            int selectedIndex = random.Next(0, unassignedItems.Count);
            inventoryModel selectedDevice = unassignedItems[selectedIndex];
            var assignedItem = new AssignedDevicesModel
            {
                employee_id = employeeId,
                inventory_id = selectedDevice.inventory_id,
                created_at_utc = DateTime.UtcNow
            };
              selectedDevice.device_state = "Assigned";
              try{
                          _context.inventory.Update(selectedDevice);
            _context.SaveChanges();
            _context.AssignedDevices.Add(assignedItem);
            _context.SaveChanges();
              }catch (Exception ex){
                Console.WriteLine("Test CHeck");
                Console.WriteLine(ex.InnerException);
              }
             return "assigned";
        }
    else{
        return Ok(new { Message = "all devices are assigned" });}
    } catch(Exception ex){
        Console.WriteLine(ex.InnerException);
    }
        return null;
    }
    public class AssignDeviceData{
    public string employee_id{get;set;}
    public string device_id{get;set;}
    public string Specifications{get;set;}
}
    // public static string GenerateSecurityKey()
    // {
    //     const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //     const int keyLength = 32; // Choose a suitable key length (in characters)
    //     byte[] randomBytes = new byte[keyLength];
    //     using (var rng = new RNGCryptoServiceProvider())
    //     {
    //         rng.GetBytes(randomBytes);
    //     }
    //     StringBuilder result = new StringBuilder(keyLength);
    //     foreach (byte b in randomBytes)
    //     {
    //         result.Append(allowedChars[b % allowedChars.Length]);
    //     }
    //     return result.ToString();
    // }
    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("abjhbasjhbsjsjbjhabhshNidhi"));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            // You can add more claims as needed, e.g., roles or additional user information
        };
        var token = new JwtSecurityToken(
            issuer: "http://localhost:5099",
            audience: "http://localhost:5099",
            claims: claims,
            expires: DateTime.Now.AddMinutes(30), // Set the token expiration time as needed
            signingCredentials: credentials
        );
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }
    //populating specs
    [HttpGet("/Home/GetSpecifications/{deviceId}")]
public IActionResult GetSpecifications(int deviceId)
{
    // Here, you should write the logic to fetch the specifications based on the selected device ID.
    // For example:
    // var specifications = GetSpecificationsFromBackend(deviceId);
    // For demonstration purposes, let's assume we have a list of specifications related to the selected device ID:
    var specifications = _context.inventory
        .Where(s => s.device_id == deviceId)
        .Select(s => new { Value = s.Specifications, Text = s.Specifications }).Distinct()
        .ToList();
    // Return the specifications as JSON
    return Json(specifications);
}
//add user
[HttpPost("/Home/Admin/AddUser")]
public async Task<IActionResult> AddUser(UserInfoModel UserInfo)
{
    if (_context.UserInfo.Any(e => e.employee_id == UserInfo.employee_id))
    {
        return BadRequest(new { error = "User id already exists." });
    }
    string hashedpassword = HashPassword(UserInfo.password);
    var user = new  UserInfoModel
    {
        employee_id = UserInfo.employee_id,
        username = UserInfo.username,
        password = hashedpassword
    };
    _context.UserInfo.Add(user);
    await _context.SaveChangesAsync();
    return Ok("User added successfully");
}
[HttpGet("/Home/Admin/GetUsername")]
public ActionResult<UserData> GetUsername(){
    var userData=new UserData();
    string userName=_httpContextAccessor.HttpContext.Session.GetString("Username");
    var user=_context.UserInfo.FirstOrDefault(u=>u.username==userName);
    userData.username=user.username;
    userData.employee_id=user.employee_id;
    return userData;
}
public class UserData{
    public string username {get;set;}
    public int employee_id{get;set;}
}
// API endpoint to add a device to the inventory
//add to inventory
[HttpPost("/Home/Admin/AddToInventory")]
public IActionResult AddToInventory([FromBody] inventoryModel inventoryEntry)
{
  
    var device = _context.Device.FirstOrDefault(d => d.device_id == inventoryEntry.device_id);
    if (device == null)
    {
        return NotFound("Device not found.");
    }

    inventoryEntry.device_id = device.device_id;
    inventoryEntry.created_at_utc = DateTime.UtcNow;
    inventoryEntry.updated_at_utc = DateTime.UtcNow;
    inventoryEntry.device_state="Not Assigned";

        inventoryEntry.Specifications = inventoryEntry.Specifications;
    Console.WriteLine(inventoryEntry.Specifications);
    _context.inventory.Add(inventoryEntry);
    _context.SaveChanges();
    return Ok();
}
// public class inventoryData{
//     public int device_id{get; set;}
//     public string Specifications{get;set;}
// }
// [HttpPost("/Home/Admin/AddToInventory")]
// public IActionResult AddToInventory([FromBody] inventoryData inventoryEntry){
//     var newEntry= new inventoryModel{
//         device_id=inventoryEntry.device_id,
//         updated_at_utc=DateTime.UtcNow,
//         device_state="Not Assigned",
//     };
//     _context.inventory.Add(newEntry);
//     _context.SaveChanges();
//     return Ok();
// }

// [HttpDelete("/Home/Admin/DeallocateDevice")]
// public ActionResult<string> DeallocateDevice(int employeeId, int deviceId){
// var user=_context.AssignedDevices.Select(u=> u.employee_id==employeeId );
// }
 public class EmployeeDeviceData
    {
        public int EmployeeId { get; set; }
        public Guid InventoryId { get; set; }
        public string DeviceName { get; set; }
    }
    private List<AssignedDevicesModel> QueryAssignedTable(int employeeId)
    {
        return _context.AssignedDevices.Where(device => device.employee_id == employeeId).ToList();
    }
    private List<inventoryModel> QueryInventoryTable(Guid inventoryId)
    {
        return _context.inventory.Where(inventory => inventory.inventory_id == inventoryId).ToList();
    }
    public class getEmployeeData{
        public int  employee_id {get;set;}  
    }
    [HttpGet("/Home/Admin/DisplayDevices/GetEmployeeDeviceData")]
   public ActionResult<IEnumerable<EmployeeDeviceData>> GetEmployeeDeviceData([FromQuery] int employee_id)
{
    Console.WriteLine(employee_id);
    if (employee_id <= 0)
    {
        return BadRequest("Please provide a valid Employee ID.");
    }
    List<EmployeeDeviceData> employeeData = new List<EmployeeDeviceData>();
    //  Query assigned table and get inventory ids
    List<AssignedDevicesModel> assignedDevices = QueryAssignedTable(employee_id);
    List<Guid> inventoryIds = assignedDevices.Select(device => device.inventory_id).ToList();
    // Query inventory table and get device_ids
    foreach (Guid inventoryId in inventoryIds)
    {
        List<inventoryModel> inventoryData = QueryInventoryTable(inventoryId);
        if (inventoryData != null)
        {
            employeeData.Add(new EmployeeDeviceData
            {
                EmployeeId = employee_id,
                InventoryId = inventoryId,
                DeviceName = _context.Device.Find( inventoryData.FirstOrDefault(u => u.inventory_id == inventoryId).device_id).device_name,
            });
        }
    }
    return employeeData;
}
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
