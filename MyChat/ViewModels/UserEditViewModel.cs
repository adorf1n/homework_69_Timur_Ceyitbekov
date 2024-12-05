using System.ComponentModel.DataAnnotations;

namespace MyChat.ViewModels;

public class UserEditViewModel
{
    public int Id { get; set; }
    [Required(ErrorMessage = "Укажите логин!")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "Требуется адрес электронной почты!")]
    [EmailAddress(ErrorMessage = "Неверный адрес электронной почты!")]
    public string Email { get; set; }
    
    [Required(ErrorMessage = "Неверная ссылка на аватар!")]
    [Url]
    public string Avatar { get; set; }
}