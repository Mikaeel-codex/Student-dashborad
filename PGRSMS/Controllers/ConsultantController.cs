using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Pgrsms.Controllers
{
    [Authorize(Roles = "Consultant")]
    public class ConsultantController : Controller
    {
        [HttpGet("Consultant")]
        public IActionResult Index() => View();
    }
}
