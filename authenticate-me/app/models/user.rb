class User < ApplicationRecord
  has_secure_password
  before_validation :ensure_session_token

  # validates :username, presence: true, uniqueness: true
  # validates :password, length: {minimum: 6}, allow_nil: true
  # validates :email, presence: true, uniqueness: true

  validates :username,
  uniqueness: true,
  length: { in: 3..30 },
  format: { without: URI::MailTo::EMAIL_REGEXP, message:  "can't be an email" }
validates :email,
  uniqueness: true,
  length: { in: 3..255 },
  format: { with: URI::MailTo::EMAIL_REGEXP }
validates :session_token, presence: true, uniqueness: true
validates :password, length: { in: 6..255 }, allow_nil: true

def self.find_by_credentials(username, password)
  user = User.find_by(username: username)
  user&.authenticate(password) ? user : nil
end

def generate_unique_session_token
  while true
    session_token = SecureRandom::urlsafe_base64(16)
    return session_token unless User.exists?(session_token: session_token)
  end
end

def reset_session_token!
    self.session_token = generate_unique_session_token
    self.save!
    session_token
end

def ensure_session_token
  self.session_token ||= generate_unique_session_token
end

end



# class User < ApplicationRecord
#   has_secure_password

#   validates :username,
#     uniqueness: true,
#     length: { in: 3..30 },
#     format: { without: URI::MailTo::EMAIL_REGEXP, message:  "can't be an email" }
#   validates :email,
#     uniqueness: true,
#     length: { in: 3..255 },
#     format: { with: URI::MailTo::EMAIL_REGEXP }
#   validates :session_token, presence: true, uniqueness: true
#   validates :password, length: { in: 6..255 }, allow_nil: true

#   before_validation :ensure_session_token

#   def self.find_by_credentials(credential, password)
#     field = credential =~ URI::MailTo::EMAIL_REGEXP ? :email : :username
#     user = User.find_by(field => credential)
#     user&.authenticate(password)
#   end

#   def reset_session_token!
#     self.update!(session_token: generate_unique_session_token)
#     self.session_token
#   end

#   private

#   def generate_unique_session_token
#     loop do
#       token = SecureRandom.base64
#       break token unless User.exists?(session_token: token)
#     end
#   end

#   def ensure_session_token
#     self.session_token ||= generate_unique_session_token
#   end
# end
