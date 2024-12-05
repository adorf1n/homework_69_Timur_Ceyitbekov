using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyChat.Models;

namespace MyChat.Controllers;

public class ChatController : Controller
{
    private readonly UserManager<User> _userManager;
    private readonly MyChatContext _context;

    public ChatController(UserManager<User> userManager, MyChatContext context)
    {
        _userManager = userManager;
        _context = context;
    }

    public IActionResult Index()
    {
        var messages = _context.Messages
            .Include(m => m.User)
            .OrderByDescending(m => m.DateOfDispatch)
            .Take(30)
            .ToList()
            .OrderBy(m => m.DateOfDispatch) 
            .ToList();

        return View(messages);
    }

    
    [HttpPost]
    public async Task<IActionResult> Create(Message message)
    {
        if (string.IsNullOrWhiteSpace(message.Inscription))
        {
            return BadRequest(new { error = "Сообщение не может быть пустым." });
        }

        var creator = await _userManager.GetUserAsync(User);
        if (creator == null)
        {
            return Unauthorized(new { error = "Не удалось определить пользователя." });
        }

        message.UserId = creator.Id;
        message.DateOfDispatch = DateTime.UtcNow;
        _context.Messages.Add(message);
        await _context.SaveChangesAsync();

        return Json(new
        {
            avatar = creator.Avatar,
            dateOfDispatch = message.DateOfDispatch.ToString("dd.MM.yyyy HH:mm:ss"),
            userName = creator.UserName,
            userid = creator.Id,
            inscription = message.Inscription,
            messageId = message.Id
        });
    }

    [HttpGet]
    [ResponseCache(Duration = 5, Location = ResponseCacheLocation.Client, NoStore = false)]
    public IActionResult GetLatestMessages(DateTime? lastMessageTime)
    {
        var query = _context.Messages
            .Include(m => m.User)
            .OrderByDescending(m => m.DateOfDispatch)
            .Take(30);

        if (lastMessageTime.HasValue)
        {
            query = query.Where(m => m.DateOfDispatch > lastMessageTime.Value);
        }

        var messages = query
            .Select(m => new
            {
                m.Id,
                m.Inscription,
                m.DateOfDispatch,
                UserName = m.User.UserName,
                Avatar = m.User.Avatar,
                m.UserId,
                IsAdmin = User.IsInRole("admin")
            })
            .OrderBy(m => m.DateOfDispatch) 
            .ToList();
        return Json(new { messages, currentUser = User.Identity.Name });
    }

    
    [HttpPost]
    [Authorize(Roles = "admin")]
    public async Task<IActionResult> DeleteMessage(int messageId)
    {
        var message = await _context.Messages.FindAsync(messageId);
        if (message == null)
        {
            return NotFound(new { error = "Сообщение не найдено." });
        }

        _context.Messages.Remove(message);
        await _context.SaveChangesAsync();

        return Ok(new { success = true, messageId });
    }
}
