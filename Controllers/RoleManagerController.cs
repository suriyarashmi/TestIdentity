using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace MyMvcApp.Controllers
{
    [Authorize(Roles = "Admin")] // Only Admin can manage roles
    public class RoleManagerController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public RoleManagerController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        // GET: List of Roles
        public IActionResult Index()
        {
            var roles = _roleManager.Roles;
            return View(roles);
        }

        // CREATE ROLE
        public IActionResult Create() => View();

        [HttpPost]
        public async Task<IActionResult> Create(string roleName)
        {
            if (!string.IsNullOrWhiteSpace(roleName))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
                if (result.Succeeded)
                    return RedirectToAction(nameof(Index));
                else
                    ModelState.AddModelError("", "Error creating role");
            }
            return View();
        }

        // DELETE ROLE
        [HttpPost]
        public async Task<IActionResult> Delete(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role != null)
            {
                var result = await _roleManager.DeleteAsync(role);
                if (result.Succeeded)
                    return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        // MANAGE USERS
        public IActionResult Users()
        {
            var users = _userManager.Users;
            return View(users);
        }

        // ASSIGN ROLE TO USER
        public async Task<IActionResult> ManageUserRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            ViewBag.UserName = user.UserName;
            var roles = _roleManager.Roles;
            var userRoles = await _userManager.GetRolesAsync(user);

            ViewBag.UserRoles = userRoles;
            return View(roles);
        }

        [HttpPost]
        public async Task<IActionResult> AddRoleToUser(string userId, string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null && await _roleManager.RoleExistsAsync(roleName))
            {
                var result = await _userManager.AddToRoleAsync(user, roleName);
                if (result.Succeeded)
                    return RedirectToAction("ManageUserRoles", new { userId });
            }
            return RedirectToAction("Users");
        }

        [HttpPost]
        public async Task<IActionResult> RemoveRoleFromUser(string userId, string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await _userManager.RemoveFromRoleAsync(user, roleName);
                if (result.Succeeded)
                    return RedirectToAction("ManageUserRoles", new { userId });
            }
            return RedirectToAction("Users");
        }
    }
}
