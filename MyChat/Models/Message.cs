namespace MyChat.Models;

public class Message
{
    public int Id { get; set; }
    public string Inscription { get; set; }
    public DateTime DateOfDispatch { get; set; }
    
    public int? UserId { get; set; }
    public User? User { get; set; }
}