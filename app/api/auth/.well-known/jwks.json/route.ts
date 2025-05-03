import { NextResponse } from "next/server";
import { auth } from "../../../../auth";

export async function GET() {
  return NextResponse.json({
    keys: []
  });

}
