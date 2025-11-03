using Microsoft.AspNetCore.Mvc;


namespace Pgrsms.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index() => View();
    }
}