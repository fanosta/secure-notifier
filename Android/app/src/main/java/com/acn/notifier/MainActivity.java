package com.acn.notifier;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.vision.barcode.Barcode;

public class MainActivity extends Activity {
  TextView text_view;

  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.activity_main);
    text_view = findViewById(R.id.textView);
  }

  public void scanBarcode(View view) {
    Intent intent = new Intent(this, ScannerActivity.class);
    startActivityForResult(intent, 0);
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);

    if (requestCode == 0) {
      if (resultCode == CommonStatusCodes.SUCCESS) {
        if (data != null) {
          final Barcode barcode = data.getParcelableExtra("received");
          text_view.setText(barcode.displayValue);
        } else {
          text_view.setText("error");
        }
      }
    }
  }
}
