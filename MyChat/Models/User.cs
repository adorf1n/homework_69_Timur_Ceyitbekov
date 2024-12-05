using Microsoft.AspNetCore.Identity;

namespace MyChat.Models;

public class User : IdentityUser<int>
{
    public string Avatar { get; set; }
    public DateTime DateOfBirth { get; set; }
    
    public ICollection<Message> Messages { get; set; } = new List<Message>();
}