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
             return RedirectToAction("Admin");
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
// [HttpGet("/Home/Admin/GetUsername")]
// public ActionResult<UserData> GetUsername(){
//     var userData=new UserData();
//     string userName=_httpContextAccessor.HttpContext.Session.GetString("Username");
//     var user=_context.UserInfo.FirstOrDefault(u=>u.username==userName);
//     userData.username=user.username;
//     userData.employee_id=user.employee_id;
//     return userData;
// }
// public class UserData{
//     public string username {get;set;}
//     public int employee_id{get;set;}
// }
// API endpoint to add a device to the inventory
[HttpPost("/Home/Admin/AddToInventory")]
public IActionResult AddToInventory([FromBody] inventoryModel inventoryEntry, string specifications)
{
    // Retrieve the device based on the selected device_id
    var device = _context.Device.FirstOrDefault(d => d.device_id == inventoryEntry.device_id);
    if (device == null)
    {
        return NotFound("Device not found.");
    }
    // Set the created_at_utc and updated_at_utc properties
    inventoryEntry.device_id = device.device_id;
    inventoryEntry.created_at_utc = DateTime.UtcNow;
    inventoryEntry.updated_at_utc = DateTime.UtcNow;
    inventoryEntry.device_state="Not Assigned";
    // If specifications are not provided or empty, set it to "NA"
    // if (string.IsNullOrWhiteSpace(specifications))
    // {
    //     inventoryEntry.Specifications = "NA";
    // }
    // else
    // {
        inventoryEntry.Specifications = specifications;
    // }
    // Add the inventory entry to the database
    _context.inventory.Add(inventoryEntry);
    _context.SaveChanges();
    return Ok();
}
//   private readonly Dictionary<string, int[]> dataMap = new Dictionary<string, int[]>
//     {
//         { "option1", new int[] { , 30, 30 } },
//         { "option2", new int[] { 10, 50, 40 } },
//         { "option3", new int[] { 20, 20, 60 } },
//         { "option4", new int[] { 25, 35, 40 } }
//     };
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
