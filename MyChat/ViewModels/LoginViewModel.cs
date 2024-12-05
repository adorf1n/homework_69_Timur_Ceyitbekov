using System.ComponentModel.DataAnnotations;

namespace MyChat.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Неверный логин или почта!")]
    public string Identifier { get; set; }
    [Required(ErrorMessage = "Требуется пароль!")]
    [DataType(DataType.Password)]
    [MinLength(6, ErrorMessage = "Минимальная длина пароля 6 символов")]
    public string Password { get; set; }
    public bool RememberMe { get; set; }
    public string? ReturnUrl { get; set; }
}