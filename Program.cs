using System.Text;
using ITGateway.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Session;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<DataContext>(options =>
        {
            options.UseSqlServer(builder.Configuration.GetConnectionString("MyConnection")); // Configure SQL Server connection
        });
        var key=Encoding.ASCII.GetBytes("abjhbasjhbsjsjbjhabhshNidhi");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                        .AddJwtBearer(options =>
                        {
                            options.TokenValidationParameters = new TokenValidationParameters
                            {
                                ValidateIssuer = true,
                                ValidateAudience = true,
                                ValidateIssuerSigningKey = true,
                                ValidIssuer = "http://localhost:5099",
                                ValidAudience = "http://localhost:5099",
                                IssuerSigningKey = new SymmetricSecurityKey(key)
                            };
                        });
//  builder.Services.AddDistributedSqlServerCache(options =>
//         {
//             options.ConnectionString = builder.Configuration.GetConnectionString("MyConnection");
//             options.SchemaName = "dbo"; // Optional: Set the schema name for the database table
//             options.TableName = "Sessions"; // Set the table name for storing sessions
//         });
builder.Services.AddHttpContextAccessor();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(60);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
// app.UseSession();
    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();

    app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
