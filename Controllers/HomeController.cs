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
using Microsoft.AspNetCore.Authorization;
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




    public IActionResult Index()
    {
        return View();
    }
       public IActionResult ErrorPage()
    {
        return View();
    }
    public IActionResult Privacy()
    {
        return View();
    }
    [HttpGet("/Home/Admin")]
    public IActionResult Admin()
    {
        if (HttpContext.User.IsInRole("Admin")){
        List<DevicesModel> devices = GetDevicesFromBackend();
        return View(devices);
        }
        else{
            return View("ErrorPage");
        }
    }


    //perform authorization on basis of role generated in jwt token

    [HttpGet("/Home/User")]
public IActionResult User()
{
      if (HttpContext.User.IsInRole("User")){
            List<DevicesModel> devices = GetDevicesFromBackend();
            return View(devices);
      }
    
        else
        {
            return View("ErrorPage");
        }

}


    private List<DevicesModel> GetDevicesFromBackend()
    {
        var devicesList = new List<DevicesModel>();
        try
        {
            devicesList = _context.Device.ToList();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.InnerException);
        }
        return devicesList;
    }
    private string HashPassword(string password)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }


    [HttpPost("/Login")]
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
            Console.WriteLine(token);
            Response.Cookies.Append("JwtToken", token);
            _httpContextAccessor.HttpContext.Session.SetString("Username", user.username);
            _httpContextAccessor.HttpContext.Session.SetString("JwtToken", token);
            string x = _httpContextAccessor.HttpContext.Session.GetString("Username");
            Console.WriteLine(x);
            var emp = _context.employees.Find(user.employee_id);

            if (emp.IsAdmin == 1)
            {
                return Ok("Admin");
            }
            else if (emp.IsAdmin == 0)
            {
                
                return Ok("User");
            }
        }
        return Ok("Invalid username or password.");
    }


    [HttpGet("Home/User/CheckAvailability")]
    public ActionResult<string> CheckAvailability(int deviceId, string specifications)
    {
        if (HttpContext.User.IsInRole("User")){
        var user = _context.inventory.FirstOrDefault(u => u.device_id == deviceId && u.Specifications == specifications);
        if (user == null)
        {
            return "Not Available";
        }

        return "Available";
        }
        else{
            return View("ErrorPage");
        }
    }


    [HttpGet("Home/User/GetUserDevices")]
    public ActionResult<IEnumerable<EmployeeDeviceData>> GetUserDevices()
    {
        if (HttpContext.User.IsInRole("User")){
        string userName = _httpContextAccessor.HttpContext.Session.GetString("Username");
        var user = _context.UserInfo.FirstOrDefault(u => u.username == userName);
        int employee_id = user.employee_id;
        Console.WriteLine(employee_id);
        Console.WriteLine(employee_id);
        if (employee_id <= 0)
        {
            return BadRequest("Please provide a valid Employee ID.");
        }
        List<EmployeeDeviceData> employeeData = new List<EmployeeDeviceData>();

        List<AssignedDevicesModel> assignedDevices = QueryAssignedTable(employee_id);
        List<Guid> inventoryIds = assignedDevices.Select(device => device.inventory_id).ToList();

        foreach (Guid inventoryId in inventoryIds)
        {
            List<inventoryModel> inventoryData = QueryInventoryTable(inventoryId);
            if (inventoryData != null)
            {
                employeeData.Add(new EmployeeDeviceData
                {

                    
                    EmployeeId = employee_id,
                    InventoryId = inventoryId,
                    DeviceName = _context.Device.Find(inventoryData.FirstOrDefault(u => u.inventory_id == inventoryId).device_id).device_name,
                });
            }
        }
        return employeeData;}
        else{
            return View("ErrorPage");
        }
    }
public class DeviceRequestModel
    {
        public string deviceName { get; set; }
    }
   
    [HttpPost("/Home/Admin/AddDevice")]
    public IActionResult AddDevice([FromBody]DeviceRequestModel request)
    {
        if (HttpContext.User.IsInRole("Admin")){
            Console.WriteLine("x"+request.deviceName);
        if (string.IsNullOrEmpty(request.deviceName))
        {
            return BadRequest("Device name is required.");
        }
        string userName = _httpContextAccessor.HttpContext.Session.GetString("Username");
        Console.WriteLine("username" + userName);
        var device = new DevicesModel
        {
            device_name = request.deviceName,
            created_by = userName,
            created_at_utc = DateTime.UtcNow,
            updated_at_utc = DateTime.UtcNow
        };
        if (_context.Device.Any(d => d.device_name == device.device_name))
        {
            return Json(new { Message = "Device already exists." });
        }
        _context.Device.Add(device);
        _context.SaveChanges();

        return Json(new { Message = "Device added successfully." });
        }
        else{
            return View("ErrorPage");
        }
    }
    [HttpPost("/Home/Admin/AssignDevice")]

    public ActionResult<string> AssignDevice([FromBody] AssignDeviceData Data)
    {   if (HttpContext.User.IsInRole("Admin")){
        try
        {
            int deviceId = int.Parse(Data.device_id);
            int employeeId = int.Parse(Data.employee_id);
            List<inventoryModel> inventoryList = _context.inventory.ToList();
            var unassignedItems = inventoryList.Where(u => u.device_id == deviceId && u.Specifications == Data.Specifications && u.device_state == "Not Assigned").ToList();
            Console.WriteLine("Total unassigned items for deviceId " + deviceId + ": " + unassignedItems.Count + " " + employeeId);
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
                try
                {
                    _context.inventory.Update(selectedDevice);
                    _context.SaveChanges();
                    _context.AssignedDevices.Add(assignedItem);
                    _context.SaveChanges();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Test CHeck");
                    Console.WriteLine(ex.InnerException);
                }
                return "assigned";
            }
            else
            {
                return Ok(new { Message = "all devices are assigned" });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.InnerException);
        }
        return null;}
        else{
            return View("ErrorPage");
        }
    }
    public class AssignDeviceData
    {
        public string employee_id { get; set; }
        public string device_id { get; set; }
        public string Specifications { get; set; }
    }

    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("abjhbasjhbsjsjbjhabhshNidhi"));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var user=_context.UserInfo.FirstOrDefault(u=>u.username==username);
        var emp=_context.employees.Find(user.employee_id);
        string role;
       
        if(emp.IsAdmin==1){
            role="Admin";
        }
        else{
            role="User";
        }
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role),

        };
       Console.WriteLine(role);
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
  
    [HttpGet("/Home/GetSpecifications/{deviceId}")]
    public IActionResult GetSpecifications(int deviceId)
    {
        var specifications = _context.inventory
            .Where(s => s.device_id == deviceId)
            .Select(s => new { Value = s.Specifications, Text = s.Specifications }).Distinct()
            .ToList();
        return Json(specifications);
    }
    
    [HttpPost("/Home/Admin/AddUser")]
    public async Task<IActionResult> AddUser(UserInfoModel UserInfo)
    {
        if (HttpContext.User.IsInRole("Admin")){
        if (_context.UserInfo.Any(e => e.employee_id == UserInfo.employee_id))
        {
            return BadRequest(new { error = "User id already exists." });
        }
        string hashedpassword = HashPassword(UserInfo.password);
        var user = new UserInfoModel
        {
            employee_id = UserInfo.employee_id,
            username = UserInfo.username,
            password = hashedpassword
        };
        _context.UserInfo.Add(user);
        await _context.SaveChangesAsync();
        return Ok("User added successfully");
        }
        else{
            return View("ErrorPage");
        }
    }
    [HttpGet("/Home/Admin/GetUsername")]
    public ActionResult<UserData> GetUsername()
    {
        if (HttpContext.User.IsInRole("Admin")){
        var userData = new UserData();
        string userName = _httpContextAccessor.HttpContext.Session.GetString("Username");
        var user = _context.UserInfo.FirstOrDefault(u => u.username == userName);
        userData.username = user.username;
        userData.employee_id = user.employee_id;
        return userData;
        }
        else{
            return View("ErrorPage");
        }
    }
   
    [HttpGet("/Home/User/GetUserName")]
    public ActionResult<UserData> GetUserName()
    {
        if (HttpContext.User.IsInRole("User")){
        var userData = new UserData();
        string userName = _httpContextAccessor.HttpContext.Session.GetString("Username");
        var user = _context.UserInfo.FirstOrDefault(u => u.username == userName);
        userData.username = user.username;
        userData.employee_id = user.employee_id;
        return userData;
        }
        else{
            return View("ErrorPage");
        }
    }
    public class UserData
    {
        public string username { get; set; }
        public int employee_id { get; set; }
    }
    // [Authorize]
    [HttpPost("/Home/Admin/AddToInventory")]
    public IActionResult AddToInventory([FromBody] inventoryModel inventoryEntry)
    {
        if (HttpContext.User.IsInRole("Admin")){
        var device = _context.Device.FirstOrDefault(d => d.device_id == inventoryEntry.device_id);
        if (device == null)
        {
            return NotFound("Device not found.");
        }

        inventoryEntry.device_id = device.device_id;
        inventoryEntry.created_at_utc = DateTime.UtcNow;
        inventoryEntry.updated_at_utc = DateTime.UtcNow;
        inventoryEntry.device_state = "Not Assigned";

        inventoryEntry.Specifications = inventoryEntry.Specifications;
        Console.WriteLine(inventoryEntry.Specifications);
        _context.inventory.Add(inventoryEntry);
        _context.SaveChanges();
        return Ok();
        }
        else{
            return View("ErrorPage");
        }
    }

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
    public class getEmployeeData
    {
        public int employee_id { get; set; }
    }
    [HttpGet("/Home/Admin/DisplayDevices/GetEmployeeDeviceData")]
    public ActionResult<IEnumerable<EmployeeDeviceData>> GetEmployeeDeviceData([FromQuery] int employee_id)
    {
        if (HttpContext.User.IsInRole("Admin")){
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
                    DeviceName = _context.Device.Find(inventoryData.FirstOrDefault(u => u.inventory_id == inventoryId).device_id).device_name,
                });
            }
        }
        return employeeData;
        }
        else{
            return View("ErrorPage");
        }
    }
    public class inventoryData
    {
        public int serial { get; set; }
        public Guid inventory_id { get; set; }
        public string Specifications { get; set; }
    }
    [HttpGet("/Home/Admin/GetInventoryTable")]

    public ActionResult<IEnumerable<inventoryData>> GetInventoryTable(string deviceState, int device_id)
    {
        if (HttpContext.User.IsInRole("Admin")){
        var filteredInventory = _context.inventory // Replace with your actual DbSet name
         .Where(inventory => inventory.device_state == deviceState && inventory.device_id == device_id)
         .ToList(); // Fetch data into memory

        var indexedInventory = filteredInventory.Select((inventory, index) => new inventoryData
        {
            serial = index + 1, // Assign serial number based on index in memory
            inventory_id = inventory.inventory_id,
            Specifications = inventory.Specifications
        })
        .ToList();
        Console.WriteLine(indexedInventory);
        return indexedInventory;
        }
        else{
            return View("ErrorPage");
        }
    }



    [HttpDelete("/Home/Admin/DeleteDevice")]
    //delet device through inventory id and employee id
    public IActionResult DeleteDevice(int employee_id, string inventory_id1)
    {
        

        if (HttpContext.User.IsInRole("Admin")){
            Console.WriteLine(employee_id);
            Console.WriteLine("y"+inventory_id1);
            Guid inventory_id = Guid.Parse(inventory_id1);
            
        var assignedDevice = _context.AssignedDevices.FirstOrDefault(device => device.employee_id == employee_id && device.inventory_id == inventory_id);
        if (assignedDevice != null)
        {
            _context.AssignedDevices.Remove(assignedDevice);
            _context.SaveChanges();
            return Ok("deleted"); 
        }
        return Ok("Device not found.");}
        else{
            return View("ErrorPage");
        }
    }
 
    [HttpGet("/Home/Logout")]
    public IActionResult Logout()
    {
        // Response.Cookies.Delete("JwtToken");
           foreach (var cookie in Request.Cookies.Keys)
    {
        Response.Cookies.Delete(cookie);
    }
        _httpContextAccessor.HttpContext.Session.Clear();
        return RedirectToPage("/Index");
    }
    public class PieChartData{
        public int DeviceId { get; set; }
        public string DeviceName { get; set; }
        public int AssignedDevices { get; set; }
        public int UnassignedDevices { get; set; }
        public int RepairDevices { get; set;}
    }
    
    [HttpGet("Home/Admin/PopulatePieChart")]
public ActionResult<IEnumerable<PieChartData>> PopulatePieChart(int deviceId)
{
    if (HttpContext.User.IsInRole("Admin"))
    {
        var pieChartData = new List<PieChartData>();
        var deviceList = _context.Device.ToList();
        
        foreach (var device in deviceList)
        {
            var inventoryList = _context.inventory.Where(inventory => inventory.device_id == device.device_id).ToList();
            var assignedDevices = inventoryList.Where(inventory => inventory.device_state == "Assigned").ToList();
            var unassignedDevices = inventoryList.Where(inventory => inventory.device_state == "Not Assigned").ToList();
            var repairDevices = inventoryList.Where(inventory => inventory.device_state == "Repair").ToList();

            if (device.device_id == deviceId)
            {
                pieChartData.Add(new PieChartData
                {
                    DeviceId = device.device_id,
                    DeviceName = device.device_name,
                    AssignedDevices = assignedDevices.Count,
                    UnassignedDevices = unassignedDevices.Count,
                    RepairDevices = repairDevices.Count
                });
            }
        }
        return Json(pieChartData);
    }
    else
    {
        return View("ErrorPage");
    }
}


    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
