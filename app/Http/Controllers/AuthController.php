<?php

namespace App\Http\Controllers;

use App\Http\Requests\ForgotRequest;
use App\Http\Requests\ResetRequest;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Mail\Message;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        $fields = $request->validate([
            'username' => 'required|string|unique:users',
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([

            'username' => $fields['username'],
            'first_name' => $fields['first_name'],
            'last_name' => $fields['last_name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])

        ]);

        $token = $user->createToken('_Token')->plainTextToken;

        $response = [
            'status' => 'success',
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {

        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string|min:6'
        ]);

        //Check  Email
        $user = User::where('email', $fields['email'])->first();

        //Check  Password
        if (!$user  || !Hash::check($fields['password'], $user->password)) {
            return response([
                'status' => 'Failed',
                'message' => 'Credentials not match'
            ], 401);
        }

        $token = $user->createToken('_Token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response([
            'status' => "succes",
            "message" => "Login successful",
            'data' => $response
        ], 201);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return [
            'message' => 'Logged out'
        ];
    }

    public function currentUser(Request $request)
    {
        return $request->user();
    }

    public function forgotPassword(ForgotRequest $request)
    {
        $email = $request->input('email');
        if (User::where('email', $email)->doesntExist()) {
            return response([
                'message' => 'User does not exists!'
            ], 404);
        }
        $token = Str::random(10);
        try {

            DB::table('password_resets')->insert([
                'email' => $email,
                'token' => $token
            ]);

            Mail::send('Mails.forgot', ['token' => $token], function (Message $message) use ($email) {
                $message->to($email);
                $message->subject('Reset your password');
            });

            return response([
                'message' => 'Check your Email'
            ]);
        } catch (\Exception $exception) {
            return response([
                'message' => $exception->getMessage()
            ], 400);
        }
    }

    public function resetPassword(ResetRequest $request)
    {
        $token = $request->input('token');
        if (!$passwordResets = DB::table('password_resets')->where('token', $token)->first()) {
            return response([
                'message' => 'Invalid token'
            ],400);
        }

        /** @var User $user */
        if(!$user = User::where('email',$passwordResets->email)->first()){
            return response([
                'message' => 'User does not exist!'
            ],404);
        }

        $user->password =Hash::make($request->input('password'));
        $user->save();

        return response([
            'message' => 'Success'
        ]);
    }
}
