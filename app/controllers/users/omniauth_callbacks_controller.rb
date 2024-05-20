# frozen_string_literal: true

class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def google_oauth2
    allowed_domain = 'aptonworks.com'
    user_email = auth.info.email

    if user_email.ends_with?("@#{allowed_domain}")
      user = User.from_omniauth(auth)

      if user.persisted?
        sign_out_all_scopes
        flash[:success] = t 'devise.omniauth_callbacks.success', kind: 'Google'
        sign_in_and_redirect user, event: :authentication
      else
        user.save
        flash[:alert] = t 'devise.omniauth_callbacks.failure', kind: 'Google', reason: "#{user_email} is not authorized."
        redirect_to new_user_session_path
      end
    else
      flash[:alert] = t 'devise.omniauth_callbacks.failure', kind: 'Google', reason: "#{user_email} is not authorized."
      redirect_to new_user_session_path
    end
  end

  protected

  def after_omniauth_failure_path_for(_scope)
    new_user_session_path
  end

  def after_sign_in_path_for(resource_or_scope)
    stored_location_for(resource_or_scope) || root_path
  end

  private

  def auth
    @auth ||= request.env['omniauth.auth']
  end
end
