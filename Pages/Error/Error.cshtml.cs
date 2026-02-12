using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages.Error
{
    public class ErrorModel : PageModel
    {
        public int StatusCode { get; set; }

        public void OnGet(int? statusCode)
        {
            StatusCode = statusCode ?? 500;
        }
    }
}
