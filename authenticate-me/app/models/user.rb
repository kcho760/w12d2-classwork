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