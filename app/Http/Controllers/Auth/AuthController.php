<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
   public function register(Request $request){

        // dd($request);
        $data = $request->validate([
            'name' => ['required', 'string'],
            'email' => ['required', 'email', 'unique:users'],
            'password' => ['required', 'min:6']
        ]);
        
        $user = User::create($data);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
        ]);
   }

   public function login(Request $request){

    $data = $request->validate([
        'email' => ['required', 'email', 'exists:users'],
        'password' => ['required', 'min:6']
    ]);

    $user = User::where('email', $data['email'])->first();

    if(!$user || !Hash::check($data['password'], $user->password)){
        return response([
            'message' => 'Bad creds'
        ], 401);
    }

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
        'user' => $user,
        'token' => $token,
    ]);

    
}

    public function logout(Request $request){

        $request->user()->currentAccessToken()->delete();
        return response()->json(['message'=> 'Berhasil log out.']);
    }
}
