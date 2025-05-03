import { NextRequest, NextResponse } from "next/server";
import { auth } from "../../../../auth";

export async function POST(request: NextRequest) {
  const body = await request.json();
  
  try {
    const client = await auth.oauth2.register({
      name: body.name,
      redirect_uris: body.redirect_uris,
    });
    
    return NextResponse.json(client);
  } catch (error) {
    console.error("Error registering client:", error);
    return NextResponse.json({ error: "Failed to register client" }, { status: 500 });
  }
}
