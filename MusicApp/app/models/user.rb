# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  email           :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#
class User < ApplicationRecord
    before_validation :ensure_session_token #what is this vs. after-initialize

    validates :email, :session_token, presence:true,uniqueness:true
    validates :password_digest, presence:true
    validates :password, length: {minimum: 6, allow_nil:true}

    def self.find_by_credentials(email, password)
        user = User.find_by(email: email)
        if user && user.is_password?(password)
            user
        else
            nil
        end
    end

    def self.generate_session_token
        SecureRandom::urlsafe_base64
    end 
    
    def reset_session_token!
        self.session_token = User.generate_session_token
        self.save!
        self.session_token
    end 
    
    def ensure_session_token
        self.session_token ||= User.generate_session_token
    end

    #Write a User#password=(password) method which actually sets the password_digest attribute using BCrypt,
    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end

    def password
        @password
    end

    def is_password?(password)
        bcrypt_object = BCrypt::Password.new(self.password_digest)
        bcrypt_object.is_password?(password)
        
    end

end
