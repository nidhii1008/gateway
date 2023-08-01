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
    string userName=_httpContextAccessor.HttpContext.Session.GetString("Username");
    Console.WriteLine("username"+userName);
    var device = new DevicesModel
    {
        device_name = deviceName,
        created_by = userName,
        // updated_by = username,
        created_at_utc = DateTime.UtcNow,
        updated_at_utc = DateTime.UtcNow
    };
    _context.Device.Add(device);
    _context.SaveChanges();
    return Ok("Device added successfully.");
}
    [HttpPost("Home/Admin")]
    public ActionResult<string> AssignDevice(int employeeID, int deviceId)
    {
        List<inventoryModel> inventoryList = _context.inventory.ToList();
        var unassignedItems = inventoryList.Where(u => u.device_id == deviceId && u.device_state == "Not Assigned").ToList();
        Console.WriteLine("Total unassigned items for deviceId " + deviceId + ": " + unassignedItems.Count+employeeID);
        if (unassignedItems.Count > 0)
        {
            Random random = new Random();
            int selectedIndex = random.Next(0, unassignedItems.Count);
            inventoryModel selectedDevice = unassignedItems[selectedIndex];
            selectedDevice.device_state = "Assigned";
            _context.SaveChanges();
            var assignedItem = new AssignedDevicesModel
            {
                employee_id = employeeID,
                inventory_id = selectedDevice.inventory_id,
                created_at_utc = DateTime.UtcNow
            };
            _context.AssignedDevices.Add(assignedItem);
            _context.SaveChanges();
            return "assigned";
        }
    else{
        return "all devices are assigned";}
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
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
