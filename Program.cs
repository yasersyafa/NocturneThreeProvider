using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NocturneThreeProvider.Database;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories;
using NocturneThreeProvider.Repositories.Interfaces;
using NocturneThreeProvider.Services;
using NocturneThreeProvider.Services.Interfaces;
using NocturneThreeProvider.Settings;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Settings binding
builder.Services.Configure<JwtSettings>(config.GetSection("Jwt"));
builder.Services.Configure<IdentitySettings>(config.GetSection("Identity"));
builder.Services.Configure<EmailSettings>(config.GetSection("Email"));

// database context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// identity
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    var identitySettings = config.GetSection("Identity").Get<IdentitySettings>()!;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 7;
    options.Lockout.AllowedForNewUsers = true;

    // Password settings
    options.Password.RequiredLength = identitySettings.RequiredLength;
    options.Password.RequireDigit = identitySettings.RequireDigit;
    options.Password.RequireUppercase = identitySettings.RequireUppercase;
    options.Password.RequireLowercase = identitySettings.RequireLowercase;
    options.Password.RequireNonAlphanumeric = identitySettings.RequireNonAlphanumeric;
    // required for verification email
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// JWT configurations
var jwt = config.GetSection("Jwt").Get<JwtSettings>()!;
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key))
    };
});

// Auto Mappers
builder.Services.AddAutoMapper(typeof(Program));

// Add repositories to the container.
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();

// Add services to the container.
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<IUserService, UserService>();

// Add API Versioning.
builder.Services.AddApiVersioning(options =>
{
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.ReportApiVersions = true;
});

builder.Services.AddVersionedApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Nocturne Three API",
        Version = "v1"
    });

    // 🔒 Tambah definisi JWT Bearer
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Masukkan token JWT seperti ini: Bearer {your token}"
    });

    // 🔒 Terapkan ke semua endpoint
    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

var apiVersionDescriptionProvider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();

app.UseSwaggerUI(options =>
{
    foreach (var description in apiVersionDescriptionProvider.ApiVersionDescriptions)
    {
        options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
            description.GroupName.ToUpperInvariant());
    }
});


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        var apiVersionDescriptionProvider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();

        foreach (var description in apiVersionDescriptionProvider.ApiVersionDescriptions)
        {
            options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
                description.GroupName.ToUpperInvariant());
        }
    });
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
