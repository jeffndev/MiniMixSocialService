class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :email
      t.string :display_name
      t.string :password

      t.boolean :email_verification, :default => false
      t.string :verification_code      

      t.string :api_authtoken
      t.datetime :authtoken_expiry

      t.timestamps null: false
    end
  end
end
