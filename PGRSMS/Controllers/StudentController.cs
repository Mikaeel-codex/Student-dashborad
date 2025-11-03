using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;

namespace Pgrsms.Controllers
{
    [Authorize(Roles = "Student,Admin,Consultant")]
    public class StudentController : Controller
    {
        private readonly IWebHostEnvironment _env;
        public StudentController(IWebHostEnvironment env) => _env = env;

        [HttpGet]
        public IActionResult Index(string? tab = null)
        {
            ViewBag.ActiveTab = string.IsNullOrWhiteSpace(tab) ? "ai" : tab;
            return View();
        }

        [ValidateAntiForgeryToken]
        [HttpPost]
        public async Task<IActionResult> UploadDoc(IFormFile? file)
        {
            if (file == null || file.Length == 0)
            {
                TempData["UploadStatus"] = "Please choose a file.";
                return RedirectToAction(nameof(Index), new { tab = "doc-upload" });
            }

            var webroot = _env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
            var uploadsDir = Path.Combine(webroot, "uploads");
            if (!Directory.Exists(uploadsDir)) Directory.CreateDirectory(uploadsDir);

            var name = Path.GetFileName(file.FileName);
            var safe = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{name}";
            var dest = Path.Combine(uploadsDir, safe);

            using var stream = System.IO.File.Create(dest);
            await file.CopyToAsync(stream);

            TempData["UploadStatus"] = $"Uploaded {name}";
            return RedirectToAction(nameof(Index), new { tab = "doc-upload" });
        }
    }
}
