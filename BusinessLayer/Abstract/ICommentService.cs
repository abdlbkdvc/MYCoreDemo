﻿using EntityLayer.Concrete;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BusinessLayer.Abstract
{
    public interface ICommentService
    {
        void CommentyAdd(Comment comment);
        //void CommentDelete(Comment comment);
        //void CommentUpdate(Comment comment);
        List<Comment> GetList(int id);
        //Comment GetById(int id);
    }
}
