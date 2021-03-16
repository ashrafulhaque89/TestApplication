using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Helpers;
using Models;
using TestApplication.Data;

namespace Services
{
    public interface IUserService
    {
        User Authenticate(string username, string password);
        IEnumerable<User> GetAll();
        User GetById(int id);
        User Create(User user, string password);
        void Update(User user, string currentPassword, string password, string confirmPassword);
        void Delete(int id);
    }

    public class UserService : IUserService
    {
        private Context _context;

        public UserService(Context context)
        {
            _context = context;
        }

        static string GenerateRandomCryptographicKey(int keyLength)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            string hashstring = "";
            foreach(var hashbyte in randomBytes)
            {
                hashstring += hashbyte.ToString("x2"); 
            }
            return hashstring;
        }

        public User Authenticate(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return null;

            var user = _context.User.SingleOrDefault(x => x.Username == username);

            // check if username exists
            if (user == null)
                return null;
            
             /* Fetch the stored value */
            string savedPasswordHash = _context.User.SingleOrDefault(x => x.Username == username).PasswordHash;
            /* Extract the bytes */
            string [] passwordparts = savedPasswordHash.Split(":");
            string hashedpassword = passwordparts[0];
            string salt = passwordparts[1];

            MD5 md5 = new MD5CryptoServiceProvider();

            byte[] result = md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password));         

            var hashstring = "";
            foreach(var hashbyte in result)
            {
                hashstring += hashbyte.ToString("x2"); 
            }

            if(hashstring != hashedpassword)
            {
                return null;
            }
            return user;        
        }

        public IEnumerable<User> GetAll()
        {
            return _context.User;
        }

        public User GetById(int id)
        {
            return _context.User.Find(id);
        }

        public User Create(User user, string password)
        {
            // validation
            if (string.IsNullOrWhiteSpace(password))
                throw new AppException("Password is required");

            if (_context.User.Any(x => x.Username == user.Username))
                throw new AppException("Username \"" + user.Username + "\" is already taken");
            
               MD5 md5 = new MD5CryptoServiceProvider();

            var salt = GenerateRandomCryptographicKey(10000);
            var exactSalt = salt.Substring(salt.Length -2);

            byte[] result = md5.ComputeHash(Encoding.UTF8.GetBytes(exactSalt + password));  
            

            var hashstring = "";
            foreach(var hashbyte in result)
            {
                hashstring += hashbyte.ToString("x2"); 
            }
            string savedPasswordHash = hashstring;

            user.PasswordHash = savedPasswordHash + ":" + exactSalt;  

            _context.User.Add(user);
            _context.SaveChanges();

            return user;
        }

        public void Update(User userParam, string currentPassword, string password, string confirmPassword)
        {
            var user = _context.User.Find(userParam.Id);

            if (user == null)
                throw new AppException("User not found");

            // update username if it has changed
            if (!string.IsNullOrWhiteSpace(userParam.Username) && userParam.Username != user.Username)
            {
                // throw error if the new username is already taken
                if (_context.User.Any(x => x.Username == userParam.Username))
                    throw new AppException("Username " + userParam.Username + " is already taken");

                user.Username = userParam.Username;
            }

            // update user properties if provided
            if (!string.IsNullOrWhiteSpace(userParam.FirstName))
                user.FirstName = userParam.FirstName;

            if (!string.IsNullOrWhiteSpace(userParam.LastName))
                user.LastName = userParam.LastName;
            
             /*Get Current password*/
            string savedPasswordHash = _context.User.SingleOrDefault(x => x.Username == userParam.Username).PasswordHash;
            /* Extract the bytes */
            string [] passwordparts = savedPasswordHash.Split(":");
            string hashedpassword = passwordparts[0];
            string salt = passwordparts[1];

            MD5 md5 = new MD5CryptoServiceProvider();

            byte[] result = md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password));         

            var hashstring = "";
            foreach(var hashbyte in result)
            {
                hashstring += hashbyte.ToString("x2"); 
            }
            if(hashstring != hashedpassword)
            throw new AppException("Invalid Current password!");

            if(currentPassword == password)
            throw new AppException("Please choose another password!");

            if(password != confirmPassword)
            throw new AppException("Password doesn't match!");

            var salts = GenerateRandomCryptographicKey(10000);
            var exactSalt = salts.Substring(salts.Length -2);

            byte[] results = md5.ComputeHash(Encoding.UTF8.GetBytes(exactSalt + password));  
            

            var hashstrings = "";
            foreach(var hashbyte in results)
            {
                hashstrings += hashbyte.ToString("x2"); 
            }
            string savedPasswordHashs = hashstrings;

            user.PasswordHash = savedPasswordHash + ":" + exactSalt;

            _context.User.Update(user);
            _context.SaveChanges();
        }

        public void Delete(int id)
        {
            var user = _context.User.Find(id);
            if (user != null)
            {
                _context.User.Remove(user);
                _context.SaveChanges();
            }
        }
    }
}