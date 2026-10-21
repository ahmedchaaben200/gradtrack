<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use OpenApi\Attributes as OA;

#[OA\Info(title: 'GradTrack API', version: '1.0.0')]
#[OA\SecurityScheme(
    securityScheme: 'sanctum',
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'Token'
)]
class AuthController extends Controller
{
    #[OA\Post(
        path: '/api/register',
        summary: 'Register a student or supervisor',
        tags: ['Auth'],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['name', 'role', 'email', 'password', 'password_confirmation', 'code'],
                properties: [
                    new OA\Property(property: 'name', type: 'string', example: 'Sara Ben Ali'),
                    new OA\Property(property: 'role', type: 'string', enum: ['student', 'supervisor']),
                    new OA\Property(property: 'email', type: 'string', format: 'email', example: 'sara@example.com'),
                    new OA\Property(property: 'password', type: 'string', format: 'password', example: 'password123'),
                    new OA\Property(property: 'password_confirmation', type: 'string', format: 'password', example: 'password123'),
                    new OA\Property(property: 'code', type: 'string', example: 'STU-8F3K2-2026'),
                ]
            )
        ),
        responses: [
            new OA\Response(response: 201, description: 'Registered successfully'),
            new OA\Response(response: 422, description: 'Validation error / invalid code'),
        ]
    )]
    public function register(RegisterRequest $request)
    {
        $user = DB::transaction(function () use ($request) {
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => $request->password,
                'role'     => $request->role,
            ]);

            $user->assignRole($request->role);

            return $user;
        });

        $token = $user->createToken('auth_token')->plainTextToken; // this line was missing

        return response()->json([
            'message' => 'Registered successfully',
            'user'    => $user->only('id', 'name', 'email', 'role'),
            'token'   => $token,
        ], 201);
    }
    #[OA\Post(
    path: '/api/login',
    summary: 'Login and get an access token',
    tags: ['Auth'],
    requestBody: new OA\RequestBody(
        required: true,
        content: new OA\JsonContent(
            required: ['email', 'password'],
            properties: [
                new OA\Property(property: 'email', type: 'string', format: 'email', example: 'sara@example.com'),
                new OA\Property(property: 'password', type: 'string', format: 'password', example: 'password123'),
            ]
        )
    ),
    responses: [
        new OA\Response(response: 200, description: 'Logged in successfully'),
        new OA\Response(response: 401, description: 'Invalid credentials'),
        new OA\Response(response: 422, description: 'Validation error'),
    ]
)]
        public function login(LoginRequest $request)
        {
            $user = User::where('email', $request->email)->first();

            if (! $user || ! Hash::check($request->password, $user->password)) {
                return response()->json(['message' => 'Invalid email or password.'], 401);
            }

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'message' => 'Logged in successfully',
                'user'    => $user->only('id', 'name', 'email', 'role'),
                'token'   => $token,
            ]);
        }

        #[OA\Post(
            path: '/api/logout',
            summary: 'Logout (revoke the current token)',
            security: [['sanctum' => []]],
            tags: ['Auth'],
            responses: [
                new OA\Response(response: 200, description: 'Logged out successfully'),
                new OA\Response(response: 401, description: 'Unauthenticated'),
            ]
        )]
        public function logout(Request $request)
        {
            $request->user()->currentAccessToken()->delete();

            return response()->json(['message' => 'Logged out successfully']);
        }

        #[OA\Get(
            path: '/api/me',
            summary: 'Get the authenticated user',
            security: [['sanctum' => []]],
            tags: ['Auth'],
            responses: [
                new OA\Response(response: 200, description: 'Current user'),
                new OA\Response(response: 401, description: 'Unauthenticated'),
            ]
        )]
        public function me(Request $request)
        {
            return response()->json([
                'user' => $request->user()->only('id', 'name', 'email', 'role'),
            ]);
        }
}