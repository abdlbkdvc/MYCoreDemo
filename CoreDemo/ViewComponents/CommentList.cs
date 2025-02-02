using CoreDemo.Models;
using Microsoft.AspNetCore.Mvc;

namespace CoreDemo.ViewComponents
{
    public class CommentList : ViewComponent
    {
        public IViewComponentResult Invoke()
        {
            var commentValues = new List<UserComment>
            {
                new UserComment
                {
                    ID = 1,
                    UserName = "Abdulbaki"
                },
                new UserComment
                {
                    ID = 2,
                    UserName = "Furkan"
                },
                 new UserComment
                {
                    ID = 3,
                    UserName = "Ahmet"
                }
            };
            return View(commentValues);
        }
    }
}
