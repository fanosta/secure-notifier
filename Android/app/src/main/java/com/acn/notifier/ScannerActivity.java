package com.acn.notifier;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.SparseArray;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.content.Intent;
import android.widget.Toast;
import androidx.core.app.ActivityCompat;

import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.vision.CameraSource;
import com.google.android.gms.vision.Detector;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;

import java.io.IOException;

public class ScannerActivity extends Activity {
  public SurfaceView camera_surface;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.scanner);

    camera_surface = findViewById(R.id.surfaceView);
    createCameraSource();
  }

  private void createCameraSource() {
    BarcodeDetector barcode_detector = new BarcodeDetector.Builder(this).build();
    final CameraSource camera_source = new CameraSource.Builder(this, barcode_detector)
        .setAutoFocusEnabled(true)
        .setRequestedPreviewSize(1600, 1024)
        .build();

    if(!barcode_detector.isOperational())
    {
      Toast.makeText(getApplicationContext(), "BarcodeDetector is not Operational", Toast.LENGTH_LONG).show();
      this.finish();
    }

    camera_surface.getHolder().addCallback(new SurfaceHolder.Callback() {
      @Override
      public void surfaceCreated(SurfaceHolder holder) {
        if (ActivityCompat.checkSelfPermission(ScannerActivity.this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_DENIED) {
          int requestCode = 100;
          ActivityCompat.requestPermissions(ScannerActivity.this, new String[] {Manifest.permission.CAMERA}, requestCode);
        }
        try {
          camera_source.start(camera_surface.getHolder());
        } catch (IOException e) {
          e.printStackTrace();
        }
      }

      @Override
      public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {

      }

      @Override
      public void surfaceDestroyed(SurfaceHolder holder) {
        camera_source.stop();
      }
    });

    barcode_detector.setProcessor(new Detector.Processor<Barcode>() {
      @Override
      public void release() {

      }

      @Override
      public void receiveDetections(Detector.Detections<Barcode> detections) {
        SparseArray<Barcode> detected_barcode = detections.getDetectedItems();

        if (detected_barcode.size() != 0) {
          Intent intent = new Intent();
          intent.putExtra("received", detected_barcode.valueAt(0));
          setResult(CommonStatusCodes.SUCCESS, intent);
          finish();
        }
      }
    });
  }
}
